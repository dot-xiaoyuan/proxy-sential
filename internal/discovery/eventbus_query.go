package discovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

type eventBusStateCursor struct {
	Signature string    `json:"s"`
	Last      time.Time `json:"t"`
	Key       string    `json:"k"`
	Version   int       `json:"v"`
}

// DevicesEventBus serves the shadow current-state table. For devices that also
// exist in the active stream projection it layers the existing rich document
// underneath the event-bus current fields, preserving UI fields during the
// controlled cutover. It never writes state.
func (r Repository) DevicesEventBus(ctx context.Context, q DeviceQuery) (map[string]any, error) {
	if q.Offset != 0 {
		return nil, fmt.Errorf("offset removed; use cursor")
	}
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 20
	}
	if q.Mode != "" && q.Mode != "passive" && q.Mode != "all" {
		return nil, fmt.Errorf("unsupported state query mode")
	}
	if q.View != "" && q.View != "iot" {
		return nil, fmt.Errorf("invalid discovery view")
	}
	if q.Window <= 0 {
		q.Window = 24 * time.Hour
	}
	signature := contentHash(struct {
		View, Search, Category, Type, Protocol, State, Domain, VLAN string
		Window                                                      int64
	}{q.View + ":" + q.Mode, q.Search, q.Category, q.DeviceType, q.Protocol, q.State, q.Domain, q.VLAN, int64(q.Window)})
	args := []any{}
	add := func(value any) string { args = append(args, value); return fmt.Sprintf("$%d", len(args)) }
	where := []string{"c.last_seen >= now() - ($" + fmt.Sprint(len(args)+1) + "::text)::interval"}
	args = append(args, fmt.Sprintf("%d seconds", int(q.Window.Seconds())))
	addFact := func(condition string) {
		where = append(where, "EXISTS(SELECT 1 FROM discovery_service_facts_shadow f WHERE f.device_key=c.device_key AND "+condition+")")
	}
	if q.View == "iot" {
		where = append(where, "(s.document->>'last_device_type') <> '' AND (s.document->>'classification_status') IN ('identified','expired','conflict')")
	}
	if q.Category != "" {
		where = append(where, "(s.document->>'category')="+add(q.Category))
	}
	if q.DeviceType != "" {
		where = append(where, "(s.document->>'device_type')="+add(q.DeviceType))
	}
	if q.State != "" {
		switch q.State {
		case "identified", "expired", "conflict", "candidate":
		default:
			return nil, fmt.Errorf("invalid discovery state")
		}
		where = append(where, "(s.document->>'classification_status')="+add(q.State))
	}
	if q.Domain != "" {
		where = append(where, "(s.document->>'domain')="+add(q.Domain))
	}
	if q.VLAN != "" {
		where = append(where, "(s.document->>'vlan')="+add(q.VLAN))
	}
	if q.Protocol != "" {
		addFact("f.protocol=" + add(q.Protocol))
	}
	if q.Mode == "passive" {
		addFact("f.protocol<>'active'")
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	if needle != "" {
		if ip := net.ParseIP(needle); ip != nil {
			addFact("f.ip=" + add(ip.String()))
		} else if mac, err := net.ParseMAC(needle); err == nil {
			addFact("f.mac=" + add(mac.String()))
		} else {
			pattern := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(needle) + "%"
			if len([]rune(needle)) >= 3 {
				pattern = "%" + pattern
			}
			p := add(pattern)
			where = append(where, "((s.document->>'name') ILIKE "+p+" OR (s.document->>'manufacturer') ILIKE "+p+" OR (s.document->>'model_name') ILIKE "+p+" OR c.facts::text ILIKE "+p+")")
		}
	}
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		var c eventBusStateCursor
		if err != nil || json.Unmarshal(raw, &c) != nil || c.Signature != signature || c.Version != 1 || c.Key == "" || c.Last.IsZero() {
			return nil, fmt.Errorf("cursor does not match discovery query")
		}
		t, k := add(c.Last), add(c.Key)
		where = append(where, "(c.last_seen<"+t+" OR (c.last_seen="+t+" AND c.device_key>"+k+"))")
	}
	limit := add(q.Limit + 1)
	query := `SELECT c.device_key,c.last_seen,
coalesce(s.document,'{}'::jsonb)||jsonb_build_object(
 'id',c.device_key,'last_seen',c.last_seen,'current',true,'generation','eventbus','freshness','new',
 'fact_count',c.fact_count,'expired_fact_count',c.expired_fact_count,'facts',c.facts)
FROM discovery_device_current_shadow c
LEFT JOIN LATERAL (
 SELECT s.document FROM stream_discovery_device_state s
 WHERE s.device_key=c.device_key
   AND EXISTS(SELECT 1 FROM stream_source_cutovers x WHERE x.epoch=s.epoch AND x.state='active')
 ORDER BY s.last_seen DESC LIMIT 1
) s ON true
WHERE ` + strings.Join(where, " AND ") + `
ORDER BY c.last_seen DESC,c.device_key LIMIT ` + limit
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	items := []map[string]any{}
	keys := []eventBusStateCursor{}
	for rows.Next() {
		var key string
		var last time.Time
		var raw []byte
		if err := rows.Scan(&key, &last, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, item)
		keys = append(keys, eventBusStateCursor{signature, last, key, 1})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	more := len(items) > q.Limit
	cursor := ""
	if more {
		items = items[:q.Limit]
		b, _ := json.Marshal(keys[q.Limit-1])
		cursor = base64.RawURLEncoding.EncodeToString(b)
	}
	freshness := map[string]any{"status": "ready", "source": "eventbus", "lag_seconds": 0, "result_version": 0}
	return map[string]any{"items": items, "has_more": more, "next_cursor": cursor, "limit": q.Limit, "window": q.Window.String(), "freshness": freshness}, nil
}
