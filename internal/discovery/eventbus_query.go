package discovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type eventBusStateCursor struct {
	Signature string    `json:"s"`
	Last      time.Time `json:"t"`
	Key       string    `json:"k"`
	Version   int       `json:"v"`
}

type eventBusTotalEntry struct {
	total int64
	at    time.Time
}

var eventBusTotals sync.Map

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
	if q.Window == 0 {
		q.Window = 24 * time.Hour
	}
	signature := contentHash(struct {
		View, Search, Category, Type, Protocol, State, Domain, VLAN string
		Window                                                      int64
	}{q.View + ":" + q.Mode, q.Search, q.Category, q.DeviceType, q.Protocol, q.State, q.Domain, q.VLAN, int64(q.Window)})
	args := []any{}
	add := func(value any) string { args = append(args, value); return fmt.Sprintf("$%d", len(args)) }
	where := []string{"(c.document->>'current' IS DISTINCT FROM 'false')", "(c.document <> '{}'::jsonb OR c.fact_count>0)"}
	if q.Window > 0 {
		where = append(where, "c.last_seen >= now() - ($"+fmt.Sprint(len(args)+1)+"::text)::interval")
		args = append(args, fmt.Sprintf("%d seconds", int(q.Window.Seconds())))
	}
	addFact := func(condition string) {
		where = append(where, "EXISTS(SELECT 1 FROM discovery_service_facts_shadow f WHERE f.device_key=c.device_key AND "+condition+")")
	}
	if q.View == "iot" {
		where = append(where, "(c.document->>'last_device_type') <> '' AND (c.document->>'classification_status') IN ('identified','expired','conflict')")
	}
	if q.Category != "" {
		where = append(where, "(c.document->>'category')="+add(q.Category))
	}
	if q.DeviceType != "" {
		where = append(where, "(c.document->>'device_type')="+add(q.DeviceType))
	}
	if q.State != "" {
		switch q.State {
		case "identified", "expired", "conflict", "candidate":
		default:
			return nil, fmt.Errorf("invalid discovery state")
		}
		where = append(where, "(c.document->>'classification_status')="+add(q.State))
	}
	if q.Domain != "" {
		where = append(where, "(c.document->>'domain')="+add(q.Domain))
	}
	if q.VLAN != "" {
		where = append(where, "(c.document->>'vlan')="+add(q.VLAN))
	}
	if q.Protocol != "" {
		addFact("f.protocol=" + add(q.Protocol))
	}
	if q.Mode == "passive" {
		// Stream-only current documents have no event-bus fact row yet. Keep them
		// visible until the fact projection catches up; devices with facts still
		// require a non-active protocol.
		where = append(where, "(c.fact_count=0 OR EXISTS(SELECT 1 FROM discovery_service_facts_shadow f WHERE f.device_key=c.device_key AND f.protocol<>'active'))")
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
			where = append(where, "((c.document->>'name') ILIKE "+p+" OR (c.document->>'manufacturer') ILIKE "+p+" OR (c.document->>'model_name') ILIKE "+p+" OR c.facts::text ILIKE "+p+")")
		}
	}
	countWhere := append([]string(nil), where...)
	countArgs := append([]any(nil), args...)
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
coalesce(nullif(c.document,'{}'::jsonb),jsonb_build_object('id',c.device_key))||jsonb_build_object(
 'id',c.device_key,'last_seen',c.last_seen,'current',true,'generation','eventbus','freshness','new',
 'fact_count',c.fact_count,'expired_fact_count',c.expired_fact_count,'facts',c.facts,
 'evidence_count',c.fact_count+c.expired_fact_count,
 'addresses',coalesce(nullif(fa.addresses,'[]'::jsonb),c.document->'addresses','[]'::jsonb),
 'current_addresses',coalesce(nullif(fa.addresses,'[]'::jsonb),c.document->'current_addresses',c.document->'addresses','[]'::jsonb),
 'protocols',coalesce(nullif(fa.protocols,'[]'::jsonb),c.document->'protocols','[]'::jsonb))
FROM discovery_device_current_shadow c
LEFT JOIN LATERAL (
 SELECT jsonb_agg(DISTINCT f.value->>'ip') FILTER (WHERE coalesce(f.value->>'ip','')<>'') AS addresses,
        jsonb_agg(DISTINCT f.value->>'protocol') FILTER (WHERE coalesce(f.value->>'protocol','')<>'') AS protocols
 FROM jsonb_each(c.facts) f
) fa ON true
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
		normalizeEventBusDocument(item)
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
	result := map[string]any{"items": items, "has_more": more, "next_cursor": cursor, "limit": q.Limit, "window": q.Window.String(), "freshness": freshness}
	cacheKey := fmt.Sprintf("%p|%s", r.DB, signature)
	var total int64
	if cached, ok := eventBusTotals.Load(cacheKey); ok {
		entry := cached.(eventBusTotalEntry)
		if time.Since(entry.at) < 5*time.Second {
			total = entry.total
		}
	}
	if total == 0 {
		if countErr := r.DB.QueryRowContext(ctx, `SELECT count(*) FROM discovery_device_current_shadow c WHERE `+strings.Join(countWhere, " AND "), countArgs...).Scan(&total); countErr == nil {
			eventBusTotals.Store(cacheKey, eventBusTotalEntry{total: total, at: time.Now()})
		}
	}
	result["total"] = total
	return result, nil
}

// normalizeEventBusDocument keeps the API shape stable for documents that were
// built before a field was present. The device center assumes these collection
// fields exist; a missing key used to crash the discovery page.
func normalizeEventBusDocument(item map[string]any) {
	for _, key := range []string{"capabilities", "protocols", "observations", "addresses", "current_addresses"} {
		if value, ok := item[key]; !ok || value == nil {
			item[key] = []any{}
		}
	}
	if value, ok := item["classification"]; !ok || value == nil {
		item["classification"] = map[string]any{}
	}
	if value, ok := item["facts"]; !ok || value == nil {
		item["facts"] = map[string]any{}
	}
}
