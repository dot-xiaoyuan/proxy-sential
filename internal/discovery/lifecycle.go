package discovery

import (
	"context"
	"fmt"
)

// Hot history only leaves PostgreSQL after the batch's explicit ClickHouse
// ordinal/hash verification. Case copies live in their own protected table.
func (r Repository) CleanupDiscoveryHotHistory(ctx context.Context) error {
	_, e := r.DB.ExecContext(ctx, `DELETE FROM discovery_device_changes_v2 WHERE (ingested_at,change_id) IN (SELECT d.ingested_at,d.change_id FROM discovery_device_changes_v2 d WHERE d.ingested_at<now()-interval '30 days' AND d.archive_verified_at IS NOT NULL AND NOT d.protected AND NOT EXISTS(SELECT 1 FROM risk_cases c WHERE c.ip IS NOT NULL AND host(c.ip)=d.document->'evidence'->'subject'->>'ip') AND NOT EXISTS(SELECT 1 FROM risk_case_evidence_snapshots c WHERE c.evidence->>'ip'=d.document->'evidence'->'subject'->>'ip') ORDER BY d.ingested_at,d.change_id LIMIT 1000)`)
	if e != nil {
		return e
	}
	// The projection receipt remains the durable deduplication proof. Never
	// retire an unconfirmed write or the last proof of an event's content.
	_, e = r.DB.ExecContext(ctx, `DELETE FROM discovery_normalized_receipts n USING (
 SELECT n.sensor_id,n.source_id,n.event_id,n.revision FROM discovery_normalized_receipts n
 WHERE n.first_attempt_at<now()-interval '1 year' AND n.verified_at IS NOT NULL
 AND EXISTS(SELECT 1 FROM discovery_event_receipts r WHERE (r.sensor_id,r.source_id,r.event_id,r.revision,r.content_hash)=(n.sensor_id,n.source_id,n.event_id,n.revision,n.content_hash))
 AND NOT EXISTS(SELECT 1 FROM discovery_case_evidence_v2 c WHERE (c.sensor_id,c.source_id,c.event_id,c.revision)=(n.sensor_id,n.source_id,n.event_id,n.revision))
 ORDER BY n.first_attempt_at LIMIT 1000 FOR UPDATE OF n SKIP LOCKED
 ) old WHERE (n.sensor_id,n.source_id,n.event_id,n.revision)=(old.sensor_id,old.source_id,old.event_id,old.revision)`)
	return e
}
func (r Repository) DiscoveryStatistics(ctx context.Context) (map[string]any, error) {
	// Committed changes produce durable deltas. Statistics publish independently.
	rows, e := r.DB.QueryContext(ctx, `SELECT device_type,state,count,updated_at FROM discovery_state_counts ORDER BY device_type,state`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var kind, state string
		var count int64
		var at any
		if e = rows.Scan(&kind, &state, &count, &at); e != nil {
			return nil, e
		}
		if count < 0 {
			return nil, fmt.Errorf("discovery counter invariant failed")
		}
		items = append(items, map[string]any{"device_type": kind, "state": state, "count": count, "updated_at": at})
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	var pending int64
	var oldest any
	if e = r.DB.QueryRowContext(ctx, `SELECT count(*),min(created_at) FROM discovery_count_deltas`).Scan(&pending, &oldest); e != nil {
		return nil, e
	}
	return map[string]any{"items": items, "pending_updates": pending, "oldest_pending_at": oldest}, nil
}

func (r Repository) UpdateDiscoveryStatistics(ctx context.Context) error {
	tx, e := r.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var locked bool
	if e = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(9183991)`).Scan(&locked); e != nil {
		return e
	}
	if !locked {
		return nil
	}
	_, e = tx.ExecContext(ctx, `WITH selected AS (SELECT id FROM discovery_count_deltas ORDER BY id LIMIT 1000 FOR UPDATE), removed AS (DELETE FROM discovery_count_deltas WHERE id IN (SELECT id FROM selected) RETURNING device_type,state,delta) INSERT INTO discovery_state_counts(device_type,state,count) SELECT d.device_type,d.state,coalesce(c.count,0)+d.delta FROM (SELECT device_type,state,sum(delta) delta FROM removed GROUP BY device_type,state HAVING sum(delta)<>0) d LEFT JOIN discovery_state_counts c USING(device_type,state) ORDER BY d.device_type,d.state ON CONFLICT(device_type,state) DO UPDATE SET count=EXCLUDED.count,updated_at=now()`)
	if e != nil {
		return e
	}
	return tx.Commit()
}
