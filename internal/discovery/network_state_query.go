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

// devicesNetworkState pages a sparse, transactionally maintained lookup of
// passive network-type clues. IoT last_device_type intentionally excludes
// routers and access points, so it must not drive this asset view.
func (r Repository) devicesNetworkState(ctx context.Context, q DeviceQuery) (map[string]any, error) {
	if q.Offset != 0 || q.View != "" || (q.DeviceType != "router" && q.DeviceType != "access_point") {
		return nil, fmt.Errorf("invalid discovery view or network asset query")
	}
	if q.State != "" && q.State != "identified" && q.State != "expired" {
		return nil, fmt.Errorf("invalid network asset state")
	}
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 20
	}
	signature := contentHash(struct {
		Search, Type, Protocol, State, Domain, VLAN, Capability, Category string
		Window                                                            int64
	}{q.Search, q.DeviceType, q.Protocol, q.State, q.Domain, q.VLAN, q.Capability, q.Category, int64(q.Window)})
	args := []any{}
	add := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	where := []string{"c.state='active'", "n.epoch=c.epoch", "s.epoch=n.epoch", "s.device_key=n.device_key", "s.scope_id=n.scope_id", ActiveStreamLatestPredicate}
	if q.DeviceType == "router" {
		// IGD advertises a gateway, which belongs in the router/gateway clue
		// view but remains labelled as a gateway rather than confirmed router.
		where = append(where, "n.network_device_type IN ('router','gateway')")
	} else {
		where = append(where, "n.network_device_type='access_point'")
	}
	if q.State == "expired" {
		// An expiry worker can lag behind the lease. Show that row as pending
		// expiry in history, rather than treating its stale status as current.
		where = append(where, "(n.status='expired' OR (n.status='clue' AND n.type_valid_until<=now()))")
	} else {
		// "identified" is a legacy URL filter name. The network role is
		// still a protocol clue; the response never calls it confirmed.
		where = append(where, "n.status='clue'", "n.type_valid_until>now()", "s.document->>'current'='true'")
	}
	if q.Window > 0 {
		where = append(where, "n.type_last_seen>="+add(time.Now().UTC().Add(-q.Window)))
	}
	if q.Category != "" && q.Category != "network" {
		where = append(where, "false")
	}
	if q.Domain != "" {
		where = append(where, "s.domain="+add(q.Domain))
	}
	if q.VLAN != "" {
		where = append(where, "s.vlan="+add(q.VLAN))
	}
	if q.Capability != "" {
		where = append(where, "s.document->'capabilities' ? "+add(q.Capability))
	}
	addFact := func(condition string) {
		valid := ""
		if q.State != "expired" {
			valid = " AND NOT f.withdrawn AND f.observed_at<=now() AND f.valid_until>now()"
		}
		where = append(where, "EXISTS(SELECT 1 FROM stream_discovery_facts f WHERE f.epoch=s.epoch AND f.device_key=s.device_key AND f.scope_id=s.scope_id"+valid+" AND "+condition+" OFFSET 0)")
	}
	if q.Protocol != "" {
		addFact("f.protocol=" + add(q.Protocol))
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
			where = append(where, "(lower(s.name) LIKE "+p+" ESCAPE '\\' OR lower(s.manufacturer) LIKE "+p+" ESCAPE '\\' OR lower(s.model_name) LIKE "+p+" ESCAPE '\\')")
		}
	}
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		var cursor stateCursor
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Signature != signature || cursor.Version != 4 || cursor.Key == "" || cursor.Last.IsZero() {
			return nil, fmt.Errorf("cursor does not match network asset query")
		}
		t, k := add(cursor.Last), add(cursor.Key)
		where = append(where, "(n.type_last_seen<"+t+" OR (n.type_last_seen="+t+" AND n.device_key>"+k+"))")
	}
	limit := add(q.Limit + 1)
	query := `WITH page AS MATERIALIZED (
 SELECT n.device_key,n.epoch,n.type_last_seen,s.result_version,
  CASE WHEN n.status='clue' AND n.type_valid_until<=now() THEN 'pending_expiry' ELSE n.status END AS display_status
 FROM stream_discovery_network_state n
 JOIN stream_source_cutovers c ON c.epoch=n.epoch
 JOIN stream_discovery_device_state s ON s.epoch=n.epoch AND s.device_key=n.device_key
 WHERE ` + strings.Join(where, " AND ") + `
 ORDER BY n.type_last_seen DESC,n.device_key LIMIT ` + limit + `
)
SELECT p.device_key,p.type_last_seen,p.result_version,
 s.document||jsonb_build_object('generation','fresh','freshness','new','network_type_status',p.display_status)
 FROM page p JOIN stream_discovery_device_state s ON s.epoch=p.epoch AND s.device_key=p.device_key
 ORDER BY p.type_last_seen DESC,p.device_key LIMIT ` + limit
	rows, err := r.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	items := []map[string]any{}
	keys := []stateCursor{}
	for rows.Next() {
		var key string
		var seen time.Time
		var version int64
		var raw []byte
		if err = rows.Scan(&key, &seen, &version, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		var item map[string]any
		if err = json.Unmarshal(raw, &item); err != nil {
			rows.Close()
			return nil, err
		}
		item["result_version"] = version
		normalizeEventBusDocument(item)
		items = append(items, item)
		keys = append(keys, stateCursor{Signature: signature, Last: seen, Key: key, Version: 4})
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
		encoded, err := json.Marshal(keys[q.Limit-1])
		if err != nil {
			return nil, err
		}
		cursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	fresh, err := r.StreamCurrentFreshness(ctx)
	if err != nil {
		return nil, err
	}
	// Completion covers retained facts in every currently active epoch. A
	// newly activated epoch or an unresolved repair gap restores the warning.
	var covered bool
	err = r.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM stream_source_cutovers WHERE state='active')
 AND NOT EXISTS(
  SELECT 1 FROM (SELECT DISTINCT epoch FROM stream_source_cutovers WHERE state='active') c
  LEFT JOIN stream_discovery_network_backfill_progress p ON p.epoch=c.epoch
  WHERE p.status IS DISTINCT FROM 'complete'
   OR EXISTS(SELECT 1 FROM stream_discovery_network_backfill_gaps g
    WHERE g.epoch=c.epoch AND g.resolved_at IS NULL))`).Scan(&covered)
	if err != nil {
		return nil, err
	}
	coverage := "new_observations"
	if covered {
		coverage = "complete"
	}
	return map[string]any{"items": items, "has_more": more, "next_cursor": cursor, "limit": q.Limit,
		"window": q.Window.String(), "freshness": fresh, "network_type_coverage": coverage}, nil
}
