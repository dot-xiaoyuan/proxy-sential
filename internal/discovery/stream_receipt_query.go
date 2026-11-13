package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func streamCompactEventKey(epoch, key string) bool {
	return strings.HasPrefix(key, epoch+":stream2-")
}

func streamReceiptLedger(compact bool) (string, string) {
	if compact {
		return "stream_discovery_event_keys_compact", " AND k.key_hash=sentinel_stream_discovery_key_hash($1,$2,$3)"
	}
	return "stream_discovery_event_keys", ""
}

const streamLegacyReceiptFallbackGuard = ` AND NOT EXISTS (
 SELECT 1 FROM stream_discovery_event_keys_compact kc
 WHERE kc.key_hash=sentinel_stream_discovery_key_hash($1,$2,$3)
 AND kc.epoch=$1 AND kc.scope_id=$2 AND kc.event_key=$3)`

// StreamDiscoveryReceipt is the per-event read required for a repeated fact:
// a current-state row may coalesce freshness, but its receipt is queryable as
// soon as the projection transaction commits.
func (r Repository) StreamDiscoveryReceipt(ctx context.Context, epoch, scope, eventKey string) (map[string]any, bool, error) {
	if epoch == "" || scope == "" || eventKey == "" || len(epoch) > 128 || len(scope) > 256 || len(eventKey) > 512 {
		return nil, false, fmt.Errorf("invalid stream discovery receipt key")
	}
	if strings.HasPrefix(eventKey, epoch+":stream3-") {
		receipts, err := r.streamSegmentReceipts(ctx, epoch, scope, []string{eventKey})
		if err != nil {
			return nil, false, err
		}
		receipt, found := receipts[eventKey]
		if found {
			receipt["read_observed_at"] = time.Now().UTC()
		}
		return receipt, found, nil
	}
	var hash, result, archive string
	var accepted, projected time.Time
	var bodyRef json.RawMessage
	compact := streamCompactEventKey(epoch, eventKey)
	lookup := func(compact, legacyFallback bool) error {
		table, hashPredicate := streamReceiptLedger(compact)
		if legacyFallback {
			hashPredicate += streamLegacyReceiptFallbackGuard
		}
		return r.DB.QueryRowContext(ctx, `SELECT k.content_sha256,k.first_accepted_at,r.projected_at,r.result,r.archive_state,r.body_ref
 FROM `+table+` k JOIN LATERAL (
 SELECT r.projected_at,r.result,
  CASE WHEN r.archive_state IN ('verified','failed') THEN r.archive_state
   WHEN r.archive_segment_id IS NOT NULL THEN CASE WHEN s.lanes_finalized_at IS NOT NULL THEN 'confirmed' ELSE 'pending' END
   ELSE r.archive_state END AS archive_state,r.body_ref
 FROM stream_discovery_receipts r
 LEFT JOIN stream_projection_segments s ON s.segment_id=r.archive_segment_id
  AND s.epoch=r.epoch AND s.archive_receipt_mode IN ('segment','manifest')
 WHERE r.accepted_month=k.accepted_month AND r.epoch=$1 AND r.scope_id=$2 AND r.event_key=$3
 OFFSET 0) r ON true
	WHERE k.epoch=$1 AND k.scope_id=$2 AND k.event_key=$3`+hashPredicate, epoch, scope, eventKey).Scan(&hash, &accepted, &projected, &result, &archive, &bodyRef)
	}
	err := lookup(compact, false)
	if !compact && strings.HasPrefix(eventKey, epoch+":stream-") && errors.Is(err, sql.ErrNoRows) {
		manifest, manifestErr := r.streamDeviceManifestReceipts(ctx, epoch, scope, []string{eventKey})
		if manifestErr != nil {
			return nil, false, manifestErr
		}
		if receipt, found := manifest[eventKey]; found {
			receipt["read_observed_at"] = time.Now().UTC()
			return receipt, true, nil
		}
	}
	if compact && errors.Is(err, sql.ErrNoRows) {
		manifest, manifestErr := r.streamManifestReceipts(ctx, epoch, scope, []string{eventKey})
		if manifestErr != nil {
			return nil, false, manifestErr
		}
		if receipt, found := manifest[eventKey]; found {
			receipt["read_observed_at"] = time.Now().UTC()
			return receipt, true, nil
		}
		// Earlier non-passive sources may have used this prefix in the legacy
		// ledger. Fall back only when no compact identity exists at all.
		err = lookup(false, true)
	}
	if errors.Is(err, sql.ErrNoRows) {
		if err := r.missingLegacyReceipt(ctx, epoch, scope, []string{eventKey}); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	// projected_at is the projection transaction timestamp, which can precede
	// commit. This observation is after the exact read returned a row, so it is
	// a conservative upper bound on when that receipt became query-visible.
	return map[string]any{"generation": "fresh", "epoch": epoch, "scope_id": scope, "event_key": eventKey, "content_sha256": hash,
		"first_accepted_at": accepted, "projected_at": projected, "read_observed_at": time.Now().UTC(),
		"result": result, "archive_state": archive, "body_ref": bodyRef}, true, nil
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
	byKey := make(map[string]map[string]any, len(eventKeys))
	groups := map[bool][]string{false: {}, true: {}}
	segmentKeys := make([]string, 0)
	for _, key := range eventKeys {
		if strings.HasPrefix(key, epoch+":stream3-") {
			segmentKeys = append(segmentKeys, key)
			continue
		}
		compact := streamCompactEventKey(epoch, key)
		groups[compact] = append(groups[compact], key)
	}
	segmentReceipts, err := r.streamSegmentReceipts(ctx, epoch, scope, segmentKeys)
	if err != nil {
		return nil, nil, err
	}
	for key, receipt := range segmentReceipts {
		byKey[key] = receipt
	}
	readGroup := func(keys []string, compact, legacyFallback bool) error {
		if len(keys) == 0 {
			return nil
		}
		raw, err := json.Marshal(keys)
		if err != nil {
			return err
		}
		table := "stream_discovery_event_keys"
		hashPredicate := ""
		if compact {
			table = "stream_discovery_event_keys_compact"
			hashPredicate = " AND k.key_hash=sentinel_stream_discovery_key_hash($1,$2,v.value)"
		}
		if legacyFallback {
			hashPredicate += ` AND NOT EXISTS (
 SELECT 1 FROM stream_discovery_event_keys_compact kc
 WHERE kc.key_hash=sentinel_stream_discovery_key_hash($1,$2,v.value)
 AND kc.epoch=$1 AND kc.scope_id=$2 AND kc.event_key=v.value)`
		}
		// Both the exact ledger lookup and original month bound the receipt scan.
		rows, err := r.DB.QueryContext(ctx, `SELECT k.event_key,k.content_sha256,k.first_accepted_at,r.projected_at,r.result,r.archive_state,r.body_ref
 FROM jsonb_array_elements_text($3::jsonb) AS v(value)
 CROSS JOIN LATERAL (
 SELECT k.event_key,k.content_sha256,k.first_accepted_at,k.accepted_month FROM `+table+` k
 WHERE k.epoch=$1 AND k.scope_id=$2 AND k.event_key=v.value`+hashPredicate+` OFFSET 0) k
 CROSS JOIN LATERAL (
 SELECT r.projected_at,r.result,
  CASE WHEN r.archive_state IN ('verified','failed') THEN r.archive_state
   WHEN r.archive_segment_id IS NOT NULL THEN CASE WHEN s.lanes_finalized_at IS NOT NULL THEN 'confirmed' ELSE 'pending' END
   ELSE r.archive_state END AS archive_state,r.body_ref
 FROM stream_discovery_receipts r
 LEFT JOIN stream_projection_segments s ON s.segment_id=r.archive_segment_id
  AND s.epoch=r.epoch AND s.archive_receipt_mode IN ('segment','manifest')
 WHERE r.accepted_month=k.accepted_month AND r.epoch=$1 AND r.scope_id=$2 AND r.event_key=k.event_key
 OFFSET 0) r`, epoch, scope, raw)
		if err != nil {
			return err
		}
		for rows.Next() {
			var key, hash, result, archive string
			var accepted, projected time.Time
			var bodyRef json.RawMessage
			if err := rows.Scan(&key, &hash, &accepted, &projected, &result, &archive, &bodyRef); err != nil {
				rows.Close()
				return err
			}
			byKey[key] = map[string]any{"generation": "fresh", "epoch": epoch, "scope_id": scope, "event_key": key,
				"content_sha256": hash, "first_accepted_at": accepted, "projected_at": projected,
				"result": result, "archive_state": archive, "body_ref": bodyRef}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		return nil
	}
	for _, compact := range []bool{false, true} {
		if err := readGroup(groups[compact], compact, false); err != nil {
			return nil, nil, err
		}
	}
	legacyFallback := make([]string, 0)
	for _, key := range groups[false] {
		if _, found := byKey[key]; !found && strings.HasPrefix(key, epoch+":stream-") {
			legacyFallback = append(legacyFallback, key)
		}
	}
	deviceManifest, err := r.streamDeviceManifestReceipts(ctx, epoch, scope, legacyFallback)
	if err != nil {
		return nil, nil, err
	}
	for key, item := range deviceManifest {
		byKey[key] = item
	}
	fallback := make([]string, 0)
	for _, key := range groups[true] {
		if _, found := byKey[key]; !found {
			fallback = append(fallback, key)
		}
	}
	manifest, err := r.streamManifestReceipts(ctx, epoch, scope, fallback)
	if err != nil {
		return nil, nil, err
	}
	for key, item := range manifest {
		byKey[key] = item
	}
	fallback = fallback[:0]
	for _, key := range groups[true] {
		if _, found := byKey[key]; !found {
			fallback = append(fallback, key)
		}
	}
	if err := readGroup(fallback, false, true); err != nil {
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
	legacyMissing := make([]string, 0, len(missing))
	for _, key := range missing {
		if !strings.HasPrefix(key, epoch+":stream3-") {
			legacyMissing = append(legacyMissing, key)
		}
	}
	if err := r.missingLegacyReceipt(ctx, epoch, scope, legacyMissing); err != nil {
		return nil, nil, err
	}
	// The final lookup has completed. Every returned receipt was visible by
	// this instant, including receipts found before the compact-key fallback.
	observedAt := time.Now().UTC()
	for _, item := range items {
		item["read_observed_at"] = observedAt
	}
	return items, missing, nil
}
