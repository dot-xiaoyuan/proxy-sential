package discovery

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

type stateCursor struct {
	Signature string    `json:"s"`
	Last      time.Time `json:"t"`
	Key       string    `json:"k"`
	Version   int       `json:"v"`
}

func (r Repository) DevicesState(ctx context.Context, q DeviceQuery) (map[string]any, error) {
	if q.Offset != 0 {
		return nil, fmt.Errorf("offset removed; use cursor")
	}
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 20
	}
	signature := contentHash(struct {
		View, Search, Category, Type, Protocol, State, Domain, VLAN string
		Window                                                      int64
	}{q.View + ":" + q.Mode, q.Search, q.Category, q.DeviceType, q.Protocol, q.State, q.Domain, q.VLAN, int64(q.Window)})
	args := []any{}
	where := []string{"true"}
	if q.Mode != "" && q.Mode != "passive" && q.Mode != "all" {
		return nil, fmt.Errorf("unsupported state query mode")
	}
	if q.View != "" && q.View != "iot" {
		return nil, fmt.Errorf("invalid discovery view")
	}
	if q.Mode == "passive" {
		where = append(where, "EXISTS(SELECT 1 FROM discovery_service_facts_v2 f WHERE f.device_key=s.device_key AND f.protocol<>'active')")
	}

	add := func(value any) string { args = append(args, value); return fmt.Sprintf("$%d", len(args)) }
	if q.View == "iot" {
		where = append(where, "s.last_device_type<>'' AND s.classification_status IN ('identified','expired','conflict')")
	}
	if q.Category != "" {
		where = append(where, "s.last_category="+add(q.Category))
	}
	if q.DeviceType != "" {
		where = append(where, "s.last_device_type="+add(q.DeviceType))
	}
	if q.State != "" {
		switch q.State {
		case "identified", "expired", "conflict", "candidate":
		default:
			return nil, fmt.Errorf("invalid discovery state")
		}
		where = append(where, "s.classification_status="+add(q.State))
	}
	if q.Domain != "" {
		where = append(where, "s.domain="+add(q.Domain))
	}
	if q.VLAN != "" {
		where = append(where, "s.vlan="+add(q.VLAN))
	}
	if q.Protocol != "" {
		where = append(where, "EXISTS(SELECT 1 FROM discovery_service_facts_v2 f WHERE f.device_key=s.device_key AND f.protocol="+add(q.Protocol)+")")
	}
	if q.Window > 0 {
		where = append(where, "s.last_seen>="+add(time.Now().UTC().Add(-q.Window)))
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	if needle != "" {
		if ip := net.ParseIP(needle); ip != nil {
			where = append(where, "EXISTS(SELECT 1 FROM discovery_service_facts_v2 f WHERE f.device_key=s.device_key AND f.ip="+add(ip.String())+")")
		} else if mac, e := net.ParseMAC(needle); e == nil {
			where = append(where, "EXISTS(SELECT 1 FROM discovery_service_facts_v2 f WHERE f.device_key=s.device_key AND f.mac="+add(mac.String())+")")
		} else {
			pattern := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(needle) + "%"
			if len([]rune(needle)) >= 3 {
				pattern = "%" + pattern
			}
			p := add(pattern)
			where = append(where, "(lower(s.name) LIKE "+p+" ESCAPE '\\' OR lower(s.manufacturer) LIKE "+p+" ESCAPE '\\' OR lower(s.model_name) LIKE "+p+" ESCAPE '\\')")
		}
	}
	if q.Cursor != "" {
		raw, e := base64.RawURLEncoding.DecodeString(q.Cursor)
		var c stateCursor
		if e != nil || json.Unmarshal(raw, &c) != nil || c.Signature != signature || c.Version != 2 || c.Key == "" || c.Last.IsZero() {
			return nil, fmt.Errorf("cursor does not match discovery query")
		}
		t, k := add(c.Last), add(c.Key)
		where = append(where, "(s.last_seen<"+t+" OR (s.last_seen="+t+" AND s.device_key>"+k+"))")
	}
	limit := add(q.Limit + 1)
	rows, err := r.DB.QueryContext(ctx, `SELECT s.device_key,s.last_seen,s.result_version,s.document FROM discovery_device_state_v2 s WHERE `+strings.Join(where, " AND ")+` ORDER BY s.last_seen DESC,s.device_key LIMIT `+limit, args...)
	if err != nil {
		return nil, err
	}
	items := []map[string]any{}
	keys := []stateCursor{}
	for rows.Next() {
		var key string
		var last time.Time
		var version int64
		var raw []byte
		if err = rows.Scan(&key, &last, &version, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		var item map[string]any
		if err = json.Unmarshal(raw, &item); err != nil {
			rows.Close()
			return nil, err
		}
		item["result_version"] = version
		items = append(items, item)
		keys = append(keys, stateCursor{signature, last, key, 2})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	more := len(items) > q.Limit
	cursor := ""
	if more {
		items = items[:q.Limit]
		b, _ := json.Marshal(keys[q.Limit-1])
		cursor = base64.RawURLEncoding.EncodeToString(b)
	}
	fresh, err := r.DiscoveryFreshness(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"items": items, "has_more": more, "next_cursor": cursor, "limit": q.Limit, "window": q.Window.String(), "freshness": fresh}, nil
}
func (r Repository) DiscoveryFreshness(ctx context.Context) (map[string]any, error) {
	var oldest, ingested, processed sql.NullTime
	var failure sql.NullString
	var version int64
	err := r.DB.QueryRowContext(ctx, `SELECT
 (SELECT created_at FROM discovery_batch_work WHERE NOT completed ORDER BY created_at LIMIT 1),
 (SELECT ingested_at FROM discovery_pipeline_watermark WHERE singleton),
 (SELECT processed_at FROM discovery_pipeline_watermark WHERE singleton),
 (SELECT error FROM discovery_batch_work WHERE NOT completed AND error<>'' ORDER BY created_at LIMIT 1),
 coalesce((SELECT result_version FROM discovery_device_state_v2 ORDER BY result_version DESC LIMIT 1),0)`).Scan(&oldest, &ingested, &processed, &failure, &version)
	if err != nil {
		return nil, err
	}
	status := "ready"
	lag := float64(0)
	if !processed.Valid {
		status = "initializing"
	}
	if oldest.Valid {
		lag = time.Since(oldest.Time).Seconds()
		status = "processing"
		if lag > 5 {
			status = "delayed"
		}
	}
	if failure.Valid {
		status = "failed"
	}
	result := map[string]any{"status": status, "lag_seconds": lag, "result_version": version, "error": failure.String}
	if oldest.Valid {
		result["oldest_pending_at"] = oldest.Time
	}
	if ingested.Valid {
		result["ingested_at"] = ingested.Time
	}
	if processed.Valid {
		result["processed_at"] = processed.Time
	}
	return result, nil
}
func (r Repository) DiscoveryHistory(ctx context.Context, key string, cursor string, limit int) (map[string]any, error) {
	var after int64
	if cursor != "" {
		b, e := base64.RawURLEncoding.DecodeString(cursor)
		var c struct {
			Key     string `json:"k"`
			After   int64  `json:"a"`
			Version int    `json:"v"`
		}
		if e != nil || json.Unmarshal(b, &c) != nil || c.Key != key || c.After <= 0 || c.Version != 2 {
			return nil, fmt.Errorf("invalid history cursor")
		}
		after = c.After
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT change_id,event_id,ingested_at,observed_at,change_kind,document FROM discovery_device_changes_v2 WHERE device_key=$1 AND ($2::bigint=0 OR change_id<$2) ORDER BY change_id DESC LIMIT $3`, key, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	ids := []int64{}
	for rows.Next() {
		var id int64
		var event, kind string
		var accepted, observed time.Time
		var doc json.RawMessage
		if err = rows.Scan(&id, &event, &accepted, &observed, &kind, &doc); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "event_id": event, "ingested_at": accepted, "observed_at": observed, "kind": kind, "evidence": doc})
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	more := len(items) > limit
	next := ""
	if more {
		items = items[:limit]
		b, _ := json.Marshal(map[string]any{"k": key, "a": ids[limit-1], "v": 2})
		next = base64.RawURLEncoding.EncodeToString(b)
	}
	return map[string]any{"items": items, "has_more": more, "next_cursor": next}, nil
}
