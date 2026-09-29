package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Protect all history for any case IP: legacy case snapshots do not carry a
// reliable inventory foreign key. A case without an IP fails closed globally.
const deviceRetentionReferences = `WITH protected_ips AS MATERIALIZED (
 SELECT ip FROM risk_cases
 UNION SELECT NULLIF(evidence->>'ip','')::inet FROM risk_case_evidence_snapshots
)`
const deviceRetentionProtected = deviceRetentionReferences + `, latest_runs AS MATERIALIZED (
 SELECT DISTINCT ON (sensor_id,"window") sensor_id,"window",run_id
 FROM device_inventory_snapshots ORDER BY sensor_id,"window",created_at DESC,run_id DESC
), latest_devices AS MATERIALIZED (
 SELECT DISTINCT ON (sensor_id,"window",ip) sensor_id,"window",ip,run_id
 FROM device_inventory_snapshots ORDER BY sensor_id,"window",ip,created_at DESC,run_id DESC
)`
const deviceRetentionEligible = `d.created_at < $1
 AND NOT EXISTS (SELECT 1 FROM protected_ips c WHERE c.ip IS NULL)
 AND NOT EXISTS (SELECT 1 FROM protected_ips c WHERE c.ip=d.ip)
 AND NOT EXISTS (SELECT 1 FROM latest_runs x WHERE x.sensor_id=d.sensor_id AND x."window"=d."window" AND x.run_id=d.run_id)
 AND NOT EXISTS (SELECT 1 FROM latest_devices x WHERE x.sensor_id=d.sensor_id AND x."window"=d."window" AND x.ip=d.ip AND x.run_id=d.run_id)`

type DeviceRetentionDay struct {
	Day               time.Time `json:"day"`
	Rows              int64     `json:"rows"`
	Eligible          int64     `json:"eligible"`
	InventoryBytes    int64     `json:"inventory_bytes"`
	MaxInventoryBytes int64     `json:"max_inventory_bytes"`
}
type DeviceRetentionPreview struct {
	Cutoff        time.Time            `json:"cutoff"`
	RelationBytes int64                `json:"relation_bytes"`
	Days          []DeviceRetentionDay `json:"days"`
	Protection    string               `json:"protection"`
}

type DeviceRetentionBatchError struct {
	Rows           int
	InventoryBytes int64
	Err            error
}

func (e *DeviceRetentionBatchError) Error() string {
	return fmt.Sprintf("delete retention batch (%d rows, %d inventory bytes): %v", e.Rows, e.InventoryBytes, e.Err)
}
func (e *DeviceRetentionBatchError) Unwrap() error { return e.Err }

// PreviewDeviceRetention is read-only. Counts are a point-in-time estimate;
// deletion rechecks protection on each batch.
func (s *PostgresStore) PreviewDeviceRetention(ctx context.Context, now time.Time) (DeviceRetentionPreview, error) {
	p := DeviceRetentionPreview{Cutoff: now.UTC().Add(-7 * 24 * time.Hour), Days: []DeviceRetentionDay{}, Protection: "保留案件 IP 全部历史、无 IP 案件存在时全部保留、每个传感器/窗口最新批次和每个 IP 最新快照；审计与案件证据不清理"}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
		return p, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT pg_total_relation_size('device_inventory_snapshots')").Scan(&p.RelationBytes); err != nil {
		return p, err
	}
	rows, err := tx.QueryContext(ctx, deviceRetentionProtected+` SELECT date_trunc('day',d.created_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',count(*),count(*) FILTER (WHERE `+deviceRetentionEligible+`),sum(pg_column_size(d.inventory))::bigint,max(pg_column_size(d.inventory))::bigint FROM device_inventory_snapshots d GROUP BY 1 ORDER BY 1`, p.Cutoff)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var day DeviceRetentionDay
		if err = rows.Scan(&day.Day, &day.Rows, &day.Eligible, &day.InventoryBytes, &day.MaxInventoryBytes); err != nil {
			rows.Close()
			return p, err
		}
		p.Days = append(p.Days, day)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	return p, tx.Commit()
}

// DeleteDeviceRetentionBatch never touches evidence or audit. Per-IP advisory
// locks coordinate with the database reference triggers, including all writers.
// Invoke outside ingest, with a fixed cutoff from a preview.
func (s *PostgresStore) DeleteDeviceRetentionBatch(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	if cutoff.IsZero() || cutoff.After(time.Now().UTC().Add(-7*24*time.Hour)) {
		return 0, fmt.Errorf("cutoff must retain at least seven days")
	}
	if limit < 1 || limit > 1000 {
		return 0, fmt.Errorf("batch size must be between 1 and 1000")
	}
	// Discover candidates without holding case locks. The final short transaction
	// rechecks every reference and latest snapshot, so this list is not authority.
	candidateCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(candidateCtx, deviceRetentionProtected+` SELECT d.run_id,d."window",host(d.ip),pg_column_size(d.inventory)::bigint FROM device_inventory_snapshots d WHERE `+deviceRetentionEligible+` ORDER BY d.created_at,d.run_id,d."window",d.ip LIMIT $2`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("select retention candidates: %w", err)
	}
	type candidate struct {
		Run    string `json:"run_id"`
		Window string `json:"window"`
		IP     string `json:"ip"`
	}
	candidates := []candidate{}
	var candidateBytes int64
	for rows.Next() {
		var c candidate
		var size int64
		if err = rows.Scan(&c.Run, &c.Window, &c.IP, &size); err != nil {
			rows.Close()
			return 0, err
		}
		if !retentionCandidateFits(len(candidates), candidateBytes, size) {
			break
		}
		candidates = append(candidates, c)
		candidateBytes += size
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	if len(candidates) == 0 {
		return 0, nil
	}
	raw, _ := json.Marshal(candidates)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, q := range []string{"SET LOCAL lock_timeout='250ms'", "SET LOCAL statement_timeout='5s'"} {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			return 0, fmt.Errorf("lock retention references: %w", err)
		}
	}
	var guarded bool
	err = tx.QueryRowContext(ctx, `SELECT count(*)=2 FROM pg_trigger WHERE tgname='inventory_reference_guard' AND tgenabled IN ('O','A') AND tgrelid IN ('risk_cases'::regclass,'risk_case_evidence_snapshots'::regclass) AND tgfoid=to_regprocedure('sentinel_guard_inventory_reference()')`).Scan(&guarded)
	if err != nil {
		return 0, err
	}
	if !guarded {
		return 0, fmt.Errorf("inventory reference guard migration is required before retention")
	}
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended('sentinel:inventory-reference:global',0))`).Scan(&locked); err != nil {
		return 0, err
	}
	if !locked {
		return 0, &pgconn.PgError{Code: "55P03", Message: "inventory reference global guard busy"}
	}
	ips := make([]string, 0, len(candidates))
	for _, c := range candidates {
		ips = append(ips, c.IP)
	}
	sort.Strings(ips)
	for i, ip := range ips {
		if i > 0 && ip == ips[i-1] {
			continue
		}
		if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('sentinel:inventory-reference:ip:' || $1::text,0))`, ip).Scan(&locked); err != nil {
			return 0, err
		}
		if !locked {
			return 0, &pgconn.PgError{Code: "55P03", Message: "inventory reference IP guard busy"}
		}
	}
	result, err := tx.ExecContext(ctx, deviceRetentionReferences+`, candidates AS (
 SELECT * FROM jsonb_to_recordset($2::jsonb) AS c(run_id text,"window" text,ip inet)
), victims AS (
 SELECT d.ctid FROM device_inventory_snapshots d JOIN candidates c ON d.run_id=c.run_id AND d."window"=c."window" AND d.ip=c.ip
 WHERE d.created_at < $1
 AND NOT EXISTS (SELECT 1 FROM protected_ips p WHERE p.ip IS NULL)
 AND NOT EXISTS (SELECT 1 FROM protected_ips p WHERE p.ip=d.ip)
 AND d.run_id <> (SELECT x.run_id FROM device_inventory_snapshots x WHERE x.sensor_id=d.sensor_id AND x."window"=d."window" ORDER BY x.created_at DESC,x.run_id DESC LIMIT 1)
 AND EXISTS (SELECT 1 FROM device_inventory_snapshots x WHERE x.sensor_id=d.sensor_id AND x."window"=d."window" AND x.ip=d.ip AND (x.created_at,x.run_id)>(d.created_at,d.run_id))
 FOR UPDATE OF d SKIP LOCKED
) DELETE FROM device_inventory_snapshots d USING victims v WHERE d.ctid=v.ctid`, cutoff, raw)
	if err != nil {
		return 0, &DeviceRetentionBatchError{Rows: len(candidates), InventoryBytes: candidateBytes, Err: err}
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// TOAST storage varies from kilobytes to tens of megabytes per snapshot. Keep
// normal batches under 8 MiB, but admit an oversized first row on its own so it
// cannot be silently starved. The transaction timeout still applies to it.
func retentionCandidateFits(count int, used, next int64) bool {
	const budget = int64(8 << 20)
	return count == 0 || (used <= budget && next >= 0 && next <= budget-used)
}
