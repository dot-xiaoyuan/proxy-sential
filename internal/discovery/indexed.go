package discovery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

type indexedDeviceCursor struct {
	Version     int    `json:"v"`
	Signature   string `json:"s"`
	LastSeen    string `json:"t"`
	DeviceKey   string `json:"d"`
	IdentityKey string `json:"k"`
}

func indexedDeviceSignature(q DeviceQuery) string {
	b, _ := json.Marshal(struct {
		View, Mode, Search, DeviceType, Category, Capability, Protocol, State, Domain, VLAN, ReviewReason string
		Window                                                                                            int64
		HardwareV2                                                                                        bool
	}{q.View, q.Mode, q.Search, q.DeviceType, q.Category, q.Capability, q.Protocol, q.State, q.Domain, q.VLAN, q.ReviewReason, int64(q.Window), q.HardwareV2})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func decodeIndexedDeviceCursor(q DeviceQuery) (*indexedDeviceCursor, error) {
	if q.Cursor == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid discovery cursor")
	}
	var c indexedDeviceCursor
	if json.Unmarshal(raw, &c) != nil || c.Version != 2 || c.DeviceKey == "" || c.IdentityKey == "" || c.Signature != indexedDeviceSignature(q) {
		return nil, fmt.Errorf("discovery cursor does not match query")
	}
	if _, err = time.Parse(time.RFC3339Nano, c.LastSeen); err != nil {
		return nil, fmt.Errorf("invalid discovery cursor timestamp")
	}
	return &c, nil
}

func encodeIndexedDeviceCursor(q DeviceQuery, item DeviceView) (string, error) {
	identity := item.indexedIdentityKey
	if identity == "" {
		identity = item.ID
	}
	raw, err := json.Marshal(indexedDeviceCursor{
		Version: 2, IdentityKey: identity, Signature: indexedDeviceSignature(q), LastSeen: item.LastSeen.UTC().Format(time.RFC3339Nano), DeviceKey: item.ID,
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DevicesIndexed reads the maintained latest-observation relation. It bounds
// the candidate set in SQL before decoding evidence, so a search cannot load
// the full historical device set into Go.
func (r Repository) DevicesIndexed(ctx context.Context, query DeviceQuery) (map[string]any, error) {
	return r.devicesIndexed(ctx, r.DB, query, true)
}

func (r Repository) DevicesIndexedSnapshot(ctx context.Context, tx *sql.Tx, query DeviceQuery) (map[string]any, error) {
	return r.devicesIndexed(ctx, tx, query, false)
}

type indexedQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (r Repository) devicesIndexed(ctx context.Context, db indexedQueryer, query DeviceQuery, includeFreshness bool) (map[string]any, error) {
	query.HardwareV2 = r.HardwareV2
	selection, err := buildIndexedDeviceSelection(query)
	if err != nil {
		return nil, err
	}
	query = selection.Query
	position, err := decodeIndexedDeviceCursor(query)
	if err != nil {
		return nil, err
	}
	args := selection.Args
	positionWhere := ""
	if position != nil {
		last, _ := time.Parse(time.RFC3339Nano, position.LastSeen)
		args = append(args, last, position.IdentityKey)
		positionWhere = fmt.Sprintf(" WHERE (last_seen<$%d OR (last_seen=$%d AND identity_key COLLATE \"C\">$%d))", len(args)-1, len(args)-1, len(args))
	}
	args = append(args, query.Limit+1)
	statement := selection.CTE + `, candidates AS (
 SELECT identity_key,device_key,last_seen,category FROM matched` + positionWhere + `
 ORDER BY last_seen DESC,identity_key COLLATE "C" LIMIT $` + fmt.Sprint(len(args)) + `
)
SELECT c.identity_key,c.device_key,l.data,
 -- The full link is only page metadata when it agrees with the identity used
 -- for candidate grouping. An unrelated link must not split that group.
 CASE WHEN l.linked_endpoint IS NOT NULL THEN l.linked_endpoint
  WHEN lower(coalesce(page_link.endpoint_id,''))='mac:'||lower(coalesce(l.data->>'mac','')) THEN page_link.endpoint_id
  ELSE '' END,
 l.profile_role,l.profile_confidence,l.profile_conflict,c.category
FROM candidate_rows l JOIN candidates c USING(identity_key)
LEFT JOIN discovery_identity_links page_link ON page_link.observation_id=l.id AND coalesce(l.data->>'mac','')<>''
ORDER BY c.last_seen DESC,c.identity_key COLLATE "C",l.id`
	rows, err := db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deviceRows := []deviceObservationRow{}
	categories := map[string]string{}
	for rows.Next() {
		var row deviceObservationRow
		var raw []byte
		var category string
		if err = rows.Scan(&row.IndexedIdentityKey, &row.DeviceKey, &raw, &row.EndpointID, &row.ProfileDeviceType, &row.ProfileTypeConfidence, &row.ProfileConflict, &category); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &row.Observation); err != nil {
			return nil, err
		}
		categories[row.IndexedIdentityKey] = category
		deviceRows = append(deviceRows, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	now := query.SnapshotAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	items, err := aggregateIndexedDeviceRows(deviceRows, now)
	if err != nil {
		return nil, err
	}
	if r.HardwareV2 {
		if err := attachHardwareCurrent(ctx, db, items, now); err != nil {
			return nil, err
		}
	}
	for i := range items {
		if items[i].DeviceType == "" {
			items[i].Category = categories[items[i].indexedIdentityKey]
		}
		if query.ReviewReason != "" {
			items[i].ReviewReason = query.ReviewReason
			observed := items[i].LastSeen
			if query.ReviewReason == "new_priority" {
				observed = items[i].FirstSeen
			}
			if r.HardwareV2 && query.ReviewReason == "type_change" && items[i].reviewProjectionAt != nil {
				observed = *items[i].reviewProjectionAt
			}
			if r.HardwareV2 && query.ReviewReason == "conflict" && items[i].TypeEvidenceAt != nil {
				observed = *items[i].TypeEvidenceAt
			}
			items[i].ReviewObservedAt = &observed
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].indexedIdentityKey < items[j].indexedIdentityKey
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
	hasMore := len(items) > query.Limit
	nextCursor := ""
	if hasMore {
		items = items[:query.Limit]
		nextCursor, err = encodeIndexedDeviceCursor(query, items[len(items)-1])
		if err != nil {
			return nil, err
		}
	}
	services, linked := 0, 0
	for _, item := range items {
		if len(item.Capabilities) > 0 {
			services++
		}
		if item.EndpointID != "" {
			linked++
		}
	}
	page := map[string]any{"items": items, "next_cursor": nextCursor, "has_more": hasMore, "facets": deviceFacets(items), "service_devices": services, "linked_endpoints": linked, "limit": query.Limit, "window": indexedWindowLabel(query.Window), "count_unit": "trusted_discovery_identity"}
	if r.HardwareV2 {
		page["classification_version"] = "passive-hardware/v2"
	}
	if includeFreshness {
		if r.HardwareV2 {
			page["hardware_freshness"] = r.HardwareFreshness(ctx)
		}
		if fresh := r.PassiveDiscoveryFreshness(ctx); fresh != nil {
			page["freshness"] = fresh
		}
	}
	return page, nil
}

func aggregateIndexedDeviceRows(rows []deviceObservationRow, now time.Time) ([]DeviceView, error) {
	groups := map[string][]deviceObservationRow{}
	for _, row := range rows {
		groups[row.IndexedIdentityKey] = append(groups[row.IndexedIdentityKey], row)
	}
	items := make([]DeviceView, 0, len(groups))
	for identity, rows := range groups {
		group := aggregateDeviceRows(rows, now)
		if len(group) != 1 {
			return nil, fmt.Errorf("discovery identity group invariant violated")
		}
		group[0].indexedIdentityKey = identity
		items = append(items, group[0])
	}
	return items, nil
}

func indexedWindowLabel(window time.Duration) string {
	if window < 0 {
		return "all"
	}
	return window.String()
}

func indexedOrigins(mode string) ([]string, error) {
	switch mode {
	case "passive":
		// LLDP/CDP are passive neighbor announcements and the primary router,
		// access-point and switch evidence on office segments. Keep the switch
		// forwarding tables (fdb/neighbor) in the infrastructure mode; routers
		// otherwise only surface when a fingerprint rule happens to match.
		return []string{"dhcp", "arp", "ndp", "dns_sd", "ssdp", "ws_discovery", "sadp", "ieee1905_client", "lldp", "cdp"}, nil
	case "infrastructure":
		return []string{"fdb", "neighbor", "lldp", "cdp"}, nil
	case "active":
		return []string{"active"}, nil
	case "", "all":
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid discovery mode %q", mode)
	}
}
