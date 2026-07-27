package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/risk"
)

const PostgresDDLPath = "migrations/postgres/001_production_schema.sql"

type PostgresOptions struct {
	DSN           string
	SensorID      string
	CollectorKind string
	CollectorVer  string
	InterfaceName string
}

type PostgresStore struct {
	db            *sql.DB
	dsn           string
	sensorID      string
	collectorKind string
	collectorVer  string
	interfaceName string
}

func NewPostgresStore(opts PostgresOptions) (*PostgresStore, error) {
	if err := dbRequired("postgres dsn", opts.DSN); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		return nil, err
	}
	sensorID := opts.SensorID
	if sensorID == "" {
		sensorID = "office-30"
	}
	collectorKind := opts.CollectorKind
	if collectorKind == "" {
		collectorKind = "suricata"
	}
	interfaceName := opts.InterfaceName
	if interfaceName == "" {
		interfaceName = "ens1f1"
	}
	return &PostgresStore{
		db:            db,
		dsn:           opts.DSN,
		sensorID:      sensorID,
		collectorKind: collectorKind,
		collectorVer:  opts.CollectorVer,
		interfaceName: interfaceName,
	}, nil
}

func (s *PostgresStore) DSN() string {
	return s.dsn
}

func (s *PostgresStore) collector() ingest.Collector {
	return ingest.Collector{Kind: s.collectorKind, Version: s.collectorVer, Interface: s.interfaceName}
}

func (s *PostgresStore) Overview(ctx context.Context) (Overview, error) {
	runs, err := s.ListRuns(ctx, 1)
	if err != nil {
		return Overview{}, err
	}
	counts := map[string]int{"normal": 0, "suspicious": 0, "high": 0, "confirmed": 0}
	rows, err := s.db.QueryContext(ctx, `SELECT level, count(*) FROM risk_snapshots GROUP BY level`)
	if err != nil {
		return Overview{}, fmt.Errorf("query risk level counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var level string
		var count int
		if err := rows.Scan(&level, &count); err != nil {
			return Overview{}, err
		}
		if _, ok := counts[level]; ok {
			counts[level] = count
		}
	}
	topEvidence, err := s.topEvidence(ctx)
	if err != nil {
		return Overview{}, err
	}
	latest := Run{SensorID: s.sensorID, Normalized: NormalizedCounts{ByType: map[string]int{}}}
	if len(runs) > 0 {
		latest = runs[0]
	}
	return Overview{
		LevelCounts:    counts,
		PendingReviews: counts["high"] + counts["confirmed"],
		LatestRun:      latest,
		Throughput: map[string]int{
			"events":   latest.Normalized.Emitted,
			"evidence": latest.EvidenceCount,
			"risks":    latest.RiskCount,
		},
		TopEvidence: topEvidence,
	}, nil
}

func (s *PostgresStore) ListRisks(ctx context.Context, query Query) (RiskPage, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	if query.SensorID != "" && query.SensorID != s.sensorID {
		return RiskPage{Items: []risk.Snapshot{}, Page: Page{Limit: limit}}, nil
	}
	if query.Level != "" {
		if _, ok := levelRank(query.Level); !ok {
			return RiskPage{}, fmt.Errorf("unknown level: %s", query.Level)
		}
	}
	where, args, err := riskWhere(query)
	if err != nil {
		return RiskPage{}, err
	}
	countQuery := "SELECT count(*) FROM risk_snapshots" + where
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return RiskPage{}, err
	}
	args = append(args, limit, query.Cursor)
	rows, err := s.db.QueryContext(ctx, `
SELECT host(ip), score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at
FROM risk_snapshots`+where+`
ORDER BY
  CASE level WHEN 'confirmed' THEN 3 WHEN 'high' THEN 2 WHEN 'suspicious' THEN 1 ELSE 0 END DESC,
  score DESC,
  ip ASC
LIMIT $`+strconvArg(len(args)-1)+` OFFSET $`+strconvArg(len(args)), args...)
	if err != nil {
		return RiskPage{}, err
	}
	defer rows.Close()
	items, err := scanRiskRows(rows)
	if err != nil {
		return RiskPage{}, err
	}
	var next *string
	if query.Cursor+len(items) < total {
		value := fmt.Sprintf("%d", query.Cursor+len(items))
		next = &value
	}
	return RiskPage{Items: items, Page: Page{Limit: limit, NextCursor: next, Total: total}}, nil
}

func (s *PostgresStore) GetIPRisk(ctx context.Context, ip string) (risk.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT host(ip), score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at
FROM risk_snapshots WHERE ip = $1::inet`, ip)
	if err != nil {
		return risk.Snapshot{}, err
	}
	defer rows.Close()
	items, err := scanRiskRows(rows)
	if err != nil {
		return risk.Snapshot{}, err
	}
	if len(items) == 0 {
		return normalRisk(ip), nil
	}
	return items[0], nil
}

func (s *PostgresStore) GetIPEvidence(ctx context.Context, ip string) ([]evidence.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT evidence_id, host(ip), type, "window", score, confidence, severity, reason, samples, created_at
FROM evidence WHERE ip = $1::inet ORDER BY created_at DESC, evidence_id ASC`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []evidence.Evidence{}
	for rows.Next() {
		var item evidence.Evidence
		var samples []byte
		var created time.Time
		if err := rows.Scan(&item.EvidenceID, &item.IP, &item.Type, &item.Window, &item.Score, &item.Confidence, &item.Severity, &item.Reason, &samples, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(samples, &item.Samples)
		item.CreatedAt = created.Format(time.RFC3339Nano)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	if limit == 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT run_id, sensor_id, started_at, finished_at, previous_offset, new_offset, truncated,
       normalized_read, normalized_emitted, normalized_skipped, normalized_malformed,
       evidence_count, risk_count, risk_list_count
FROM collector_runs
ORDER BY started_at DESC, run_id DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []Run{}
	for rows.Next() {
		var run Run
		var started, finished time.Time
		if err := rows.Scan(&run.RunID, &run.SensorID, &started, &finished, &run.PreviousOffset, &run.NewOffset, &run.Truncated, &run.Normalized.Read, &run.Normalized.Emitted, &run.Normalized.Skipped, &run.Normalized.Malformed, &run.EvidenceCount, &run.RiskCount, &run.RiskListCount); err != nil {
			return nil, err
		}
		run.StartedAt = started.Format(time.RFC3339Nano)
		run.FinishedAt = finished.Format(time.RFC3339Nano)
		run.Normalized.ByType = map[string]int{}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	if limit == 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT audit_id, actor, action, target, outcome, created_at
FROM audit_logs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := []AuditLog{}
	for rows.Next() {
		var log AuditLog
		var created time.Time
		if err := rows.Scan(&log.AuditID, &log.Actor, &log.Action, &log.Target, &log.Outcome, &created); err != nil {
			return nil, err
		}
		log.CreatedAt = created.Format(time.RFC3339Nano)
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

func (s *PostgresStore) WriteCollectorRun(ctx context.Context, run Run) error {
	if run.SensorID == "" {
		run.SensorID = s.sensorID
	}
	summary, _ := json.Marshal(run)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sensors(sensor_id, display_name, collector_kind, collector_version, interface_name)
VALUES($1, $1, $2, $3, $4)
ON CONFLICT(sensor_id) DO UPDATE SET collector_kind = EXCLUDED.collector_kind, collector_version = EXCLUDED.collector_version, interface_name = EXCLUDED.interface_name, updated_at = now()`,
		run.SensorID, s.collectorKind, s.collectorVer, s.interfaceName); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO collector_runs(run_id, sensor_id, started_at, finished_at, previous_offset, new_offset, truncated, normalized_read, normalized_emitted, normalized_skipped, normalized_malformed, evidence_count, risk_count, risk_list_count, summary)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT(run_id) DO UPDATE SET
  finished_at = EXCLUDED.finished_at,
  new_offset = EXCLUDED.new_offset,
  truncated = EXCLUDED.truncated,
  normalized_read = EXCLUDED.normalized_read,
  normalized_emitted = EXCLUDED.normalized_emitted,
  normalized_skipped = EXCLUDED.normalized_skipped,
  normalized_malformed = EXCLUDED.normalized_malformed,
  evidence_count = EXCLUDED.evidence_count,
  risk_count = EXCLUDED.risk_count,
  risk_list_count = EXCLUDED.risk_list_count,
  summary = EXCLUDED.summary`,
		run.RunID, run.SensorID, run.StartedAt, run.FinishedAt, run.PreviousOffset, run.NewOffset, run.Truncated, run.Normalized.Read, run.Normalized.Emitted, run.Normalized.Skipped, run.Normalized.Malformed, run.EvidenceCount, run.RiskCount, run.RiskListCount, summary); err != nil {
		return err
	}
	auditID := "audit-collector-" + run.RunID
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_logs(audit_id, actor, action, target, outcome, created_at)
VALUES($1, 'system', 'collector.run', $2, $3, $4)
ON CONFLICT(audit_id) DO UPDATE SET outcome = EXCLUDED.outcome`,
		auditID, run.RunID, fmt.Sprintf("risk_list_count=%d", run.RiskListCount), run.FinishedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) WriteEvidence(ctx context.Context, items []evidence.Evidence) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		samples, _ := json.Marshal(item.Samples)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO evidence(evidence_id, ip, type, "window", score, confidence, severity, reason, samples, created_at)
VALUES($1,$2::inet,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT(evidence_id) DO UPDATE SET score = EXCLUDED.score, confidence = EXCLUDED.confidence, severity = EXCLUDED.severity, reason = EXCLUDED.reason, samples = EXCLUDED.samples`,
			item.EvidenceID, item.IP, item.Type, item.Window, item.Score, item.Confidence, item.Severity, item.Reason, samples, item.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) WriteRiskSnapshots(ctx context.Context, snapshots []risk.Snapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, snapshot := range snapshots {
		evidenceIDs, _ := json.Marshal(snapshot.EvidenceIDs)
		payload, _ := json.Marshal(snapshot)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO risk_snapshots(ip, score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at)
VALUES($1::inet,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT(ip) DO UPDATE SET score = EXCLUDED.score, level = EXCLUDED.level, confidence = EXCLUDED.confidence, "window" = EXCLUDED."window", evidence_ids = EXCLUDED.evidence_ids, summary = EXCLUDED.summary, recommended_action = EXCLUDED.recommended_action, updated_at = EXCLUDED.updated_at`,
			snapshot.IP, snapshot.Score, snapshot.Level, snapshot.Confidence, snapshot.Window, evidenceIDs, snapshot.Summary, snapshot.RecommendedAction, snapshot.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO risk_snapshot_history(ip, snapshot) VALUES($1::inet, $2)`, snapshot.IP, payload); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) topEvidence(ctx context.Context) ([]ingest.EventTypeCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT type, count(*) FROM evidence GROUP BY type ORDER BY count(*) DESC, type ASC LIMIT 20`)
	if errors.Is(err, sql.ErrNoRows) {
		return []ingest.EventTypeCount{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ingest.EventTypeCount{}
	for rows.Next() {
		var item ingest.EventTypeCount
		if err := rows.Scan(&item.Type, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func riskWhere(query Query) (string, []any, error) {
	clauses := []string{}
	args := []any{}
	if query.Level != "" {
		args = append(args, query.Level)
		clauses = append(clauses, "level = $"+strconvArg(len(args)))
	}
	if query.Q != "" {
		args = append(args, "%"+strings.ToLower(query.Q)+"%")
		clauses = append(clauses, "(lower(host(ip)) LIKE $"+strconvArg(len(args))+" OR lower(summary) LIKE $"+strconvArg(len(args))+")")
	}
	if query.From != "" {
		if _, err := optionalTime(query.From); err != nil {
			return "", nil, fmt.Errorf("bad from: %w", err)
		}
		args = append(args, query.From)
		clauses = append(clauses, "updated_at >= $"+strconvArg(len(args))+"::timestamptz")
	}
	if query.To != "" {
		if _, err := optionalTime(query.To); err != nil {
			return "", nil, fmt.Errorf("bad to: %w", err)
		}
		args = append(args, query.To)
		clauses = append(clauses, "updated_at <= $"+strconvArg(len(args))+"::timestamptz")
	}
	if len(clauses) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

func scanRiskRows(rows *sql.Rows) ([]risk.Snapshot, error) {
	items := []risk.Snapshot{}
	for rows.Next() {
		var item risk.Snapshot
		var evidenceIDs []byte
		var updated time.Time
		if err := rows.Scan(&item.IP, &item.Score, &item.Level, &item.Confidence, &item.Window, &evidenceIDs, &item.Summary, &item.RecommendedAction, &updated); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceIDs, &item.EvidenceIDs)
		item.UpdatedAt = updated.Format(time.RFC3339Nano)
		items = append(items, item)
	}
	return items, rows.Err()
}

func strconvArg(value int) string {
	return fmt.Sprintf("%d", value)
}
