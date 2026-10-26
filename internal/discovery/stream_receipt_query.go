package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// StreamDiscoveryReceipt is the per-event read required for a repeated fact:
// a current-state row may coalesce freshness, but its receipt is queryable as
// soon as the projection transaction commits.
func (r Repository) StreamDiscoveryReceipt(ctx context.Context, epoch, scope, eventKey string) (map[string]any, bool, error) {
	if epoch == "" || scope == "" || eventKey == "" || len(epoch) > 128 || len(scope) > 256 || len(eventKey) > 512 {
		return nil, false, fmt.Errorf("invalid stream discovery receipt key")
	}
	var hash, result, archive string
	var accepted, projected time.Time
	var bodyRef json.RawMessage
	err := r.DB.QueryRowContext(ctx, `SELECT k.content_sha256,k.first_accepted_at,r.projected_at,r.result,r.archive_state,r.body_ref
 FROM stream_discovery_event_keys k JOIN LATERAL (
 SELECT r.projected_at,r.result,r.archive_state,r.body_ref FROM stream_discovery_receipts r
 WHERE r.accepted_month=k.accepted_month AND r.epoch=$1 AND r.scope_id=$2 AND r.event_key=$3
 OFFSET 0) r ON true
 WHERE k.epoch=$1 AND k.scope_id=$2 AND k.event_key=$3`, epoch, scope, eventKey).Scan(&hash, &accepted, &projected, &result, &archive, &bodyRef)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return map[string]any{"generation": "fresh", "epoch": epoch, "scope_id": scope, "event_key": eventKey, "content_sha256": hash,
		"first_accepted_at": accepted, "projected_at": projected, "result": result, "archive_state": archive, "body_ref": bodyRef}, true, nil
}

// StreamDiscoveryReceipts reads at most 50 exact keys in one bounded query.
// It uses the same ledger and partition locator as the single-event endpoint,
// so a high-rate source can verify every receipt without serial HTTP probes.
func (r Repository) StreamDiscoveryReceipts(ctx context.Context, epoch, scope string, eventKeys []string) ([]map[string]any, []string, error) {
	if epoch == "" || scope == "" || len(epoch) > 128 || len(scope) > 256 || len(eventKeys) == 0 || len(eventKeys) > 50 {
		return nil, nil, fmt.Errorf("invalid stream discovery receipt keys")
	}
	seen := make(map[string]bool, len(eventKeys))
	for _, key := range eventKeys {
		if key == "" || len(key) > 512 || seen[key] {
			return nil, nil, fmt.Errorf("invalid or duplicate stream discovery receipt key")
		}
		seen[key] = true
	}
	raw, err := json.Marshal(eventKeys)
	if err != nil {
		return nil, nil, err
	}
	// Preserve both lookup boundaries: an epoch missing from sampled planner
	// statistics must not turn a short key list into repeated history scans.
	// The original month from each ledger row also prunes receipt partitions.
	rows, err := r.DB.QueryContext(ctx, `SELECT k.event_key,k.content_sha256,k.first_accepted_at,r.projected_at,r.result,r.archive_state,r.body_ref
 FROM jsonb_array_elements_text($3::jsonb) AS v(value)
 CROSS JOIN LATERAL (
 SELECT k.event_key,k.content_sha256,k.first_accepted_at,k.accepted_month FROM stream_discovery_event_keys k
 WHERE k.epoch=$1 AND k.scope_id=$2 AND k.event_key=v.value OFFSET 0) k
 CROSS JOIN LATERAL (
 SELECT r.projected_at,r.result,r.archive_state,r.body_ref FROM stream_discovery_receipts r
 WHERE r.accepted_month=k.accepted_month AND r.epoch=$1 AND r.scope_id=$2 AND r.event_key=k.event_key
 OFFSET 0) r`, epoch, scope, raw)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	byKey := make(map[string]map[string]any, len(eventKeys))
	for rows.Next() {
		var key, hash, result, archive string
		var accepted, projected time.Time
		var bodyRef json.RawMessage
		if err := rows.Scan(&key, &hash, &accepted, &projected, &result, &archive, &bodyRef); err != nil {
			return nil, nil, err
		}
		byKey[key] = map[string]any{"generation": "fresh", "epoch": epoch, "scope_id": scope, "event_key": key,
			"content_sha256": hash, "first_accepted_at": accepted, "projected_at": projected,
			"result": result, "archive_state": archive, "body_ref": bodyRef}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	items := make([]map[string]any, 0, len(byKey))
	missing := make([]string, 0)
	for _, key := range eventKeys {
		if item, ok := byKey[key]; ok {
			items = append(items, item)
		} else {
			missing = append(missing, key)
		}
	}
	return items, missing, nil
}
