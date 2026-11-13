package discovery

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"proxy-sentinel/internal/streamlog"
)

type streamHistoryCursor struct {
	Key     string `json:"k"`
	Epoch   string `json:"e"`
	After   int64  `json:"a"`
	Version int    `json:"v"`
}

func (r Repository) streamDiscoveryHistory(ctx context.Context, epoch, key, cursor string, limit int) (map[string]any, error) {
	return r.streamDiscoveryHistoryAt(ctx, epoch, key, cursor, limit, time.Time{})
}
func (r Repository) streamDiscoveryHistoryAt(ctx context.Context, epoch, key, cursor string, limit int, snapshot time.Time) (map[string]any, error) {
	var after int64
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		var c streamHistoryCursor
		if err != nil || json.Unmarshal(raw, &c) != nil || c.Key != key || c.Epoch != epoch || c.After <= 0 || c.Version != 3 {
			return nil, fmt.Errorf("invalid fresh history cursor")
		}
		after = c.After
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	query := `SELECT c.change_id,c.event_key,c.accepted_at,c.observed_at,c.change_kind,c.before_hash,c.after_hash,c.body_ref,
 CASE WHEN left(c.event_key,char_length(c.epoch)+9)=c.epoch||':stream3-' THEN NULL
  WHEN r.event_key IS NOT NULL THEN
  CASE WHEN r.archive_state IN ('verified','failed') THEN r.archive_state
   WHEN r.archive_segment_id IS NOT NULL THEN CASE WHEN s.lanes_finalized_at IS NOT NULL THEN 'confirmed' ELSE 'pending' END
   ELSE r.archive_state END
  WHEN kc.event_key IS NOT NULL AND sm.epoch=c.epoch AND sm.source_kind='passive-discovery'
   AND sm.archive_receipt_mode='manifest' AND sm.source_file_id IS NOT NULL AND sm.source_file_id<>''
   AND sm.source_start_offset IS NOT NULL AND sm.source_end_offset>sm.source_start_offset
   AND kc.receipt_ordinal>=0 AND kc.receipt_ordinal<sm.event_count
   AND jsonb_array_length(m.results)=sm.event_count AND coalesce(m.results->>kc.receipt_ordinal,'')<>''
   AND (k.event_key IS NULL OR (k.accepted_month=kc.accepted_month AND k.content_sha256=kc.content_sha256))
   AND c.body_ref->>'class'='evidence' AND c.body_ref->>'epoch'=c.epoch
   AND c.body_ref->>'scope'=kc.scope_id AND c.body_ref->>'key'=c.event_key
   AND c.body_ref->>'sha256'=kc.content_sha256 AND c.body_ref->>'month'=m.archive_month
   AND to_char(kc.accepted_month,'YYYYMM')=m.archive_month
   AND coalesce(c.body_ref->>'body_layout','')=m.body_layout
  THEN CASE WHEN sm.lanes_finalized_at IS NOT NULL THEN 'confirmed' ELSE 'pending' END
  ELSE NULL END,
 (k.event_key IS NOT NULL OR kc.event_key IS NOT NULL)
 FROM stream_discovery_changes c
 LEFT JOIN stream_discovery_event_keys k ON k.epoch=c.epoch AND k.event_key=c.event_key AND k.scope_id=c.body_ref->>'scope'
 LEFT JOIN stream_discovery_event_keys_compact kc
  ON kc.key_hash=sentinel_stream_discovery_key_hash(c.epoch,c.body_ref->>'scope',c.event_key)
  AND kc.epoch=c.epoch AND kc.scope_id=c.body_ref->>'scope' AND kc.event_key=c.event_key
 LEFT JOIN stream_discovery_receipts r ON r.accepted_month=coalesce(kc.accepted_month,k.accepted_month)
  AND r.epoch=c.epoch AND r.scope_id=c.body_ref->>'scope' AND r.event_key=c.event_key
  AND (k.event_key IS NULL OR kc.event_key IS NULL OR
   (k.accepted_month=kc.accepted_month AND k.content_sha256=kc.content_sha256))
 LEFT JOIN stream_projection_segments s ON s.segment_id=r.archive_segment_id
  AND s.epoch=r.epoch AND s.archive_receipt_mode IN ('segment','manifest')
 LEFT JOIN stream_projection_segments sm ON sm.segment_id=kc.receipt_segment_id
 LEFT JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=sm.segment_id
 WHERE c.epoch=$1 AND c.device_key=$2 AND ($3::bigint=0 OR c.change_id<$3)
 ORDER BY c.change_id DESC LIMIT $4`
	args := []any{epoch, key, after, limit + 1}
	if !snapshot.IsZero() {
		query = strings.Replace(query, "ORDER BY c.change_id DESC", "AND c.accepted_at<=$5 ORDER BY c.change_id DESC", 1)
		args = append(args, snapshot)
	}
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	ids := []int64{}
	type segmentChange struct {
		index      int
		id         int64
		scope, key string
		accepted   time.Time
		ref        json.RawMessage
	}
	segmentChanges := make([]segmentChange, 0)
	segmentKeys := make(map[string][]string)
	for rows.Next() {
		var id int64
		var event, kind, before, afterHash string
		var archive sql.NullString
		var legacyPresent bool
		var accepted, observed time.Time
		var ref json.RawMessage
		if err = rows.Scan(&id, &event, &accepted, &observed, &kind, &before, &afterHash, &ref, &archive, &legacyPresent); err != nil {
			return nil, err
		}
		archiveState := archive.String
		if strings.HasPrefix(event, epoch+":stream3-") {
			if _, _, ok := ParsePassiveStream3Key(epoch, event); !ok || legacyPresent {
				return nil, fmt.Errorf("stream discovery change %d has conflicting stream3 identity: %w", id, streamlog.ErrContentConflict)
			}
			var fields map[string]string
			if err := json.Unmarshal(ref, &fields); err != nil || fields["scope"] == "" {
				return nil, fmt.Errorf("stream discovery change %d has invalid evidence reference: %w", id, streamlog.ErrContentConflict)
			}
			scope := fields["scope"]
			segmentChanges = append(segmentChanges, segmentChange{index: len(items), id: id, scope: scope, key: event, accepted: accepted, ref: ref})
			segmentKeys[scope] = append(segmentKeys[scope], event)
			archiveState = ""
		} else if !archive.Valid {
			if !strings.HasPrefix(event, epoch+":stream-") || !legacyPresent {
				return nil, fmt.Errorf("stream discovery change %d has no valid receipt: %w", id, streamlog.ErrUnconfirmed)
			}
			var fields map[string]string
			if err := json.Unmarshal(ref, &fields); err != nil || fields["scope"] == "" {
				return nil, fmt.Errorf("stream discovery change %d has invalid evidence reference: %w", id, streamlog.ErrContentConflict)
			}
			scope := fields["scope"]
			segmentChanges = append(segmentChanges, segmentChange{index: len(items), id: id, scope: scope, key: event, accepted: accepted, ref: ref})
			segmentKeys[scope] = append(segmentKeys[scope], event)
		}
		items = append(items, map[string]any{"id": id, "event_id": event, "ingested_at": accepted, "observed_at": observed, "kind": kind,
			"evidence": map[string]any{"before_hash": before, "after_hash": afterHash, "body_ref": ref, "archive_state": archiveState}, "generation": "fresh"})
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	segmentReceipts := make(map[string]map[string]map[string]any, len(segmentKeys))
	for scope, keys := range segmentKeys {
		receipts := make(map[string]map[string]any, len(keys))
		for start := 0; start < len(keys); start += 50 {
			batch := keys[start:min(start+50, len(keys))]
			items, missing, err := r.StreamDiscoveryReceipts(ctx, epoch, scope, batch)
			if err != nil {
				return nil, err
			}
			if len(missing) != 0 {
				return nil, streamlog.ErrUnconfirmed
			}
			for _, item := range items {
				key, ok := item["event_key"].(string)
				if !ok {
					return nil, streamlog.ErrContentConflict
				}
				receipts[key] = item
			}
		}
		segmentReceipts[scope] = receipts
	}
	for _, change := range segmentChanges {
		receipt, found := segmentReceipts[change.scope][change.key]
		if !found {
			return nil, fmt.Errorf("stream discovery change %d has no segment receipt: %w", change.id, streamlog.ErrUnconfirmed)
		}
		var original, confirmed map[string]string
		bodyRef, ok := receipt["body_ref"].(json.RawMessage)
		if !ok || json.Unmarshal(change.ref, &original) != nil || json.Unmarshal(bodyRef, &confirmed) != nil ||
			!reflect.DeepEqual(original, confirmed) || !streamAcceptedAtMatches(receipt["first_accepted_at"].(time.Time), change.accepted) {
			return nil, fmt.Errorf("stream discovery change %d has conflicting segment reference: %w", change.id, streamlog.ErrContentConflict)
		}
		items[change.index]["evidence"].(map[string]any)["archive_state"] = receipt["archive_state"]
	}
	more := len(items) > limit
	next := ""
	if more {
		items = items[:limit]
		raw, _ := json.Marshal(streamHistoryCursor{Key: key, Epoch: epoch, After: ids[limit-1], Version: 3})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	result := map[string]any{"items": items, "has_more": more, "next_cursor": next, "generation": "fresh"}
	if !snapshot.IsZero() {
		result["snapshot"] = snapshot
	}
	return result, nil
}
