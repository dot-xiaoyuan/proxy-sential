package store

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

type RiskComparison struct {
	SubjectType   string  `json:"subject_type"`
	SubjectID     string  `json:"subject_id"`
	IP            string  `json:"ip,omitempty"`
	OldScore      int     `json:"old_score"`
	NewScore      int     `json:"new_score"`
	OldLevel      string  `json:"old_level"`
	NewLevel      string  `json:"new_level"`
	OldConfidence float64 `json:"old_confidence"`
	NewConfidence float64 `json:"new_confidence"`
}
type RiskRecalculationReport struct {
	GeneratedAt       string           `json:"generated_at"`
	Window            string           `json:"window"`
	RulesetVersion    string           `json:"ruleset_version"`
	EvidenceCount     int              `json:"evidence_count"`
	PreviousCount     int              `json:"previous_count"`
	RecalculatedCount int              `json:"recalculated_count"`
	ChangedCount      int              `json:"changed_count"`
	Applied           bool             `json:"applied"`
	Changes           []RiskComparison `json:"changes"`
}

func (s *PostgresStore) RecalculateRisks(ctx context.Context, window time.Duration, rulesetVersion string, apply bool) (RiskRecalculationReport, error) {
	if window <= 0 {
		window = 7 * 24 * time.Hour
	}
	since := time.Now().UTC().Add(-window)
	items, err := s.evidenceSince(ctx, since)
	if err != nil {
		return RiskRecalculationReport{}, err
	}
	data, err := json.Marshal(evidence.Result{Evidence: items})
	if err != nil {
		return RiskRecalculationReport{}, err
	}
	batch, err := risk.Batch(bytes.NewReader(data))
	if err != nil {
		return RiskRecalculationReport{}, err
	}
	previous, err := s.currentRiskSnapshots(ctx)
	if err != nil {
		return RiskRecalculationReport{}, err
	}
	report := RiskRecalculationReport{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Window: window.String(), RulesetVersion: rulesetVersion, EvidenceCount: len(items), PreviousCount: len(previous), RecalculatedCount: len(batch.Snapshots), Changes: []RiskComparison{}, Applied: apply}
	for index := range batch.Snapshots {
		item := &batch.Snapshots[index]
		item.UpdatedAt = report.GeneratedAt
		old := previous[riskKey(*item)]
		if old.Score != item.Score || old.Level != item.Level || old.Confidence != item.Confidence {
			report.Changes = append(report.Changes, RiskComparison{SubjectType: firstNonEmpty(item.SubjectType, "ip"), SubjectID: firstNonEmpty(item.SubjectID, item.IP), IP: item.IP, OldScore: old.Score, NewScore: item.Score, OldLevel: old.Level, NewLevel: item.Level, OldConfidence: old.Confidence, NewConfidence: item.Confidence})
		}
	}
	report.ChangedCount = len(report.Changes)
	if apply {
		if err := s.archiveCurrentRiskSnapshots(ctx, previous, report.GeneratedAt, rulesetVersion); err != nil {
			return report, err
		}
		if err := s.WriteRiskSnapshots(ctx, batch.Snapshots); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (s *PostgresStore) evidenceSince(ctx context.Context, since time.Time) ([]evidence.Evidence, error) {
	items := []evidence.Evidence{}
	rows, err := s.db.QueryContext(ctx, `SELECT evidence_id,host(ip),type,"window",score,confidence,severity,reason,samples,created_at FROM evidence WHERE created_at >= $1 ORDER BY created_at`, since)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item evidence.Evidence
		var samples []byte
		var created time.Time
		if err := rows.Scan(&item.EvidenceID, &item.IP, &item.Type, &item.Window, &item.Score, &item.Confidence, &item.Severity, &item.Reason, &samples, &created); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal(samples, &item.Samples)
		item.SubjectType = "ip"
		item.SubjectID = item.IP
		item.CreatedAt = formatPostgresTime(created)
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT evidence_id,subject_type,subject_id,COALESCE(account_id,''),COALESCE(endpoint_id,''),COALESCE(host(ip),''),type,"window",score,confidence,severity,reason,samples,created_at FROM subject_evidence WHERE created_at >= $1 ORDER BY created_at`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item evidence.Evidence
		var samples []byte
		var created time.Time
		if err := rows.Scan(&item.EvidenceID, &item.SubjectType, &item.SubjectID, &item.AccountID, &item.EndpointID, &item.IP, &item.Type, &item.Window, &item.Score, &item.Confidence, &item.Severity, &item.Reason, &samples, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(samples, &item.Samples)
		item.CreatedAt = formatPostgresTime(created)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) currentRiskSnapshots(ctx context.Context) (map[string]risk.Snapshot, error) {
	items := map[string]risk.Snapshot{}
	ipItems, err := s.RiskSnapshotMap(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range ipItems {
		items[riskKey(item)] = item
	}
	rows, err := s.db.QueryContext(ctx, `SELECT subject_type,subject_id,COALESCE(account_id,''),COALESCE(endpoint_id,''),COALESCE(host(ip),''),score,level,confidence,"window",evidence_ids,summary,recommended_action,updated_at,COALESCE(assessment_level,level),COALESCE(review_disposition,''),automation_eligible,automation_blockers,detection_basis,independent_signal_groups FROM subject_risk_snapshots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item risk.Snapshot
		var evidenceIDs, blockers, signalGroups []byte
		var updated time.Time
		if err := rows.Scan(&item.SubjectType, &item.SubjectID, &item.AccountID, &item.EndpointID, &item.IP, &item.Score, &item.Level, &item.Confidence, &item.Window, &evidenceIDs, &item.Summary, &item.RecommendedAction, &updated, &item.AssessmentLevel, &item.ReviewDisposition, &item.AutomationEligible, &blockers, &item.DetectionBasis, &signalGroups); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceIDs, &item.EvidenceIDs)
		_ = json.Unmarshal(blockers, &item.AutomationBlockers)
		_ = json.Unmarshal(signalGroups, &item.IndependentSignalGroups)
		item.UpdatedAt = formatPostgresTime(updated)
		items[riskKey(item)] = item
	}
	return items, rows.Err()
}

func (s *PostgresStore) archiveCurrentRiskSnapshots(ctx context.Context, items map[string]risk.Snapshot, generatedAt, rulesetVersion string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		payload, _ := json.Marshal(map[string]any{"snapshot": item, "archived_at": generatedAt, "ruleset_version": rulesetVersion, "reason": "pre_recalculation"})
		if item.SubjectType != "" && item.SubjectType != "ip" {
			_, err = tx.ExecContext(ctx, `INSERT INTO subject_risk_snapshot_history(subject_type,subject_id,snapshot) VALUES($1,$2,$3)`, item.SubjectType, item.SubjectID, payload)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO risk_snapshot_history(ip,snapshot) VALUES($1::inet,$2)`, item.IP, payload)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func riskKey(item risk.Snapshot) string {
	if item.SubjectType != "" && item.SubjectType != "ip" {
		return item.SubjectType + ":" + item.SubjectID
	}
	return "ip:" + item.IP
}
func formatPostgresTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
