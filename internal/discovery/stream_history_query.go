package discovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type streamHistoryCursor struct {
	Key     string `json:"k"`
	Epoch   string `json:"e"`
	After   int64  `json:"a"`
	Version int    `json:"v"`
}

func (r Repository) streamDiscoveryHistory(ctx context.Context, epoch, key, cursor string, limit int) (map[string]any, error) {
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
	rows, err := r.DB.QueryContext(ctx, `SELECT c.change_id,c.event_key,c.accepted_at,c.observed_at,c.change_kind,c.before_hash,c.after_hash,c.body_ref,coalesce(r.archive_state,'pending')
 FROM stream_discovery_changes c
 LEFT JOIN stream_discovery_event_keys k ON k.epoch=c.epoch AND k.event_key=c.event_key AND k.scope_id=c.body_ref->>'scope'
 LEFT JOIN stream_discovery_receipts r ON r.accepted_month=k.accepted_month AND r.epoch=k.epoch AND r.scope_id=k.scope_id AND r.event_key=k.event_key
 WHERE c.epoch=$1 AND c.device_key=$2 AND ($3::bigint=0 OR c.change_id<$3)
 ORDER BY c.change_id DESC LIMIT $4`, epoch, key, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	ids := []int64{}
	for rows.Next() {
		var id int64
		var event, kind, before, afterHash, archive string
		var accepted, observed time.Time
		var ref json.RawMessage
		if err = rows.Scan(&id, &event, &accepted, &observed, &kind, &before, &afterHash, &ref, &archive); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "event_id": event, "ingested_at": accepted, "observed_at": observed, "kind": kind,
			"evidence": map[string]any{"before_hash": before, "after_hash": afterHash, "body_ref": ref, "archive_state": archive}, "generation": "fresh"})
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	more := len(items) > limit
	next := ""
	if more {
		items = items[:limit]
		raw, _ := json.Marshal(streamHistoryCursor{Key: key, Epoch: epoch, After: ids[limit-1], Version: 3})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return map[string]any{"items": items, "has_more": more, "next_cursor": next, "generation": "fresh"}, nil
}
