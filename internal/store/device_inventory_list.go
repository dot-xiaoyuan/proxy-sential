package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ListDeviceInventory reads the prepared endpoint summary projection. It does
// not load endpoint association histories; those belong to the detail path.
func (s *PostgresStore) ListDeviceInventory(ctx context.Context, query Query) (DeviceInventoryListPage, error) {
	now := time.Now().UTC()
	limit := query.Limit
	if limit == 0 {
		limit = 20
	}
	started := time.Now()
	conn, err := s.db.Conn(ctx)
	inventoryTiming(ctx, "pool", started)
	if err != nil {
		return DeviceInventoryListPage{}, err
	}
	defer conn.Close()

	baseWhere := []string{"e.entity_role='endpoint'"}
	baseArgs := []any{}
	if query.View == "recent" {
		baseArgs = append(baseArgs, deviceViewStart(query, now), now)
		baseWhere = append(baseWhere, "r.last_seen >= $1 AND r.last_seen <= $2")
	}
	baseSQL := " FROM endpoint_recognition_summary r JOIN endpoint_entities e USING(endpoint_id) WHERE " + strings.Join(baseWhere, " AND ")

	facets := DeviceFilterFacets{Brands: []string{}, OSFamilies: []string{}}
	if !query.InventorySkipMetadata {
		started = time.Now()
		facetRows, err := conn.QueryContext(ctx, "SELECT DISTINCT r.filter_brand,r.filter_os_family"+baseSQL, baseArgs...)
		if err != nil {
			return DeviceInventoryListPage{}, err
		}
		brandSet, osSet := map[string]string{}, map[string]string{}
		for facetRows.Next() {
			var brand, osFamily string
			if err = facetRows.Scan(&brand, &osFamily); err != nil {
				facetRows.Close()
				return DeviceInventoryListPage{}, err
			}
			if brand == "" {
				brand = "unknown"
			}
			if osFamily == "" {
				osFamily = "unknown"
			}
			brandSet[strings.ToLower(brand)] = brand
			osSet[strings.ToLower(osFamily)] = osFamily
		}
		if err = facetRows.Err(); err != nil {
			facetRows.Close()
			return DeviceInventoryListPage{}, err
		}
		facetRows.Close()
		for _, value := range brandSet {
			facets.Brands = append(facets.Brands, value)
		}
		for _, value := range osSet {
			facets.OSFamilies = append(facets.OSFamilies, value)
		}
		sort.Slice(facets.Brands, func(i, j int) bool { return strings.ToLower(facets.Brands[i]) < strings.ToLower(facets.Brands[j]) })
		sort.Slice(facets.OSFamilies, func(i, j int) bool {
			return strings.ToLower(facets.OSFamilies[i]) < strings.ToLower(facets.OSFamilies[j])
		})
		inventoryTiming(ctx, "facets", started)
	}

	where := append([]string{}, baseWhere...)
	args := append([]any{}, baseArgs...)
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, strings.ReplaceAll(clause, "$N", "$"+strconvArg(len(args))))
	}
	addExactIP := func(ip string) {
		args = append(args, ip)
		ipArg := "$" + strconvArg(len(args))
		historyWindow, sessionWindow := "", ""
		if query.View == "recent" {
			args = append(args, deviceViewStart(query, now), now)
			startArg, endArg := "$"+strconvArg(len(args)-1), "$"+strconvArg(len(args))
			historyWindow = " AND h.last_seen >= " + startArg + " AND h.first_seen <= " + endArg + " AND h.last_seen <= " + endArg
			sessionWindow = " AND s.started_at <= " + endArg + " AND (s.ended_at IS NULL OR s.ended_at >= " + startArg + ")"
		}
		where = append(where, `(EXISTS(SELECT 1 FROM identity_ip_mac_history h WHERE h.endpoint_id=r.endpoint_id AND h.ip=`+ipArg+`::inet`+historyWindow+`) OR EXISTS(SELECT 1 FROM account_sessions s WHERE s.endpoint_id=r.endpoint_id AND s.ip=`+ipArg+`::inet`+sessionWindow+`))`)
	}
	if query.Brand != "" {
		add("lower(r.filter_brand)=lower($N)", query.Brand)
	}
	if query.OSFamily != "" {
		add("lower(r.filter_os_family)=lower($N)", query.OSFamily)
	}
	if query.Ecosystem != "" {
		add("lower(r.ecosystem_hint)=lower($N)", query.Ecosystem)
	}
	if ip := net.ParseIP(strings.TrimSpace(query.SrcIP)); ip != nil {
		addExactIP(ip.String())
	}
	if ip := net.ParseIP(strings.TrimSpace(query.Q)); ip != nil {
		addExactIP(ip.String())
	} else if value := strings.TrimSpace(query.Q); value != "" {
		add(`(lower(r.device_name) LIKE $N OR lower(r.endpoint_id) LIKE $N OR lower(r.primary_mac) LIKE $N OR lower(r.current_ip) LIKE $N OR lower(r.current_account) LIKE $N OR lower(r.current_access_id) LIKE $N OR lower(coalesce(e.owner_account,'')) LIKE $N OR lower(coalesce(e.owner_name,'')) LIKE $N OR EXISTS(SELECT 1 FROM identity_ip_mac_history h WHERE h.endpoint_id=r.endpoint_id AND lower(host(h.ip)) LIKE $N) OR EXISTS(SELECT 1 FROM account_sessions s WHERE s.endpoint_id=r.endpoint_id AND (lower(host(s.ip)) LIKE $N OR lower(s.account_id) LIKE $N)))`, "%"+strings.ToLower(value)+"%")
	}
	for _, dimension := range []struct{ column, value string }{
		{"campus_id", query.CampusID}, {"department", query.Department}, {"person_type", query.PersonType},
		{"ssid", query.SSID}, {"vlan", query.VLAN}, {"ap", query.AP}, {"nas_ip", query.NASIP},
	} {
		if dimension.value == "" {
			continue
		}
		add("EXISTS(SELECT 1 FROM account_sessions s WHERE s.endpoint_id=r.endpoint_id AND s."+dimension.column+"::text=$N AND (s.ended_at IS NULL OR s.ended_at>=now()))", dimension.value)
	}

	whereSQL := " FROM endpoint_recognition_summary r JOIN endpoint_entities e USING(endpoint_id) WHERE " + strings.Join(where, " AND ")
	var total int
	if !query.InventorySkipMetadata {
		started = time.Now()
		if err = conn.QueryRowContext(ctx, "SELECT count(*)"+whereSQL, args...).Scan(&total); err != nil {
			return DeviceInventoryListPage{}, err
		}
		inventoryTiming(ctx, "count", started)
	}
	if query.InventoryMetadataOnly {
		return DeviceInventoryListPage{Items: []DeviceInventoryListItem{}, Page: Page{Total: total}, Facets: facets, AsOf: now.Format(time.RFC3339Nano)}, nil
	}
	pageLimit := limit
	if query.InventorySkipMetadata {
		pageLimit++
	}
	pageArgs := append(append([]any{}, args...), pageLimit, query.Cursor)
	started = time.Now()
	rows, err := conn.QueryContext(ctx, `SELECT r.list_item,r.updated_at`+whereSQL+`
ORDER BY r.last_seen DESC NULLS LAST,r.endpoint_id
LIMIT $`+strconvArg(len(pageArgs)-1)+` OFFSET $`+strconvArg(len(pageArgs)), pageArgs...)
	if err != nil {
		return DeviceInventoryListPage{}, err
	}
	defer rows.Close()
	items := make([]DeviceInventoryListItem, 0, limit)
	endpointIDs := make([]string, 0, limit)
	var asOf time.Time
	hasNext := false
	for rows.Next() {
		var raw []byte
		var updatedAt time.Time
		if err = rows.Scan(&raw, &updatedAt); err != nil {
			return DeviceInventoryListPage{}, err
		}
		if len(items) == limit {
			hasNext = true
			continue
		}
		var item EndpointDeviceInventory
		if err = json.Unmarshal(raw, &item); err != nil {
			return DeviceInventoryListPage{}, err
		}
		items = append(items, ProjectDeviceInventoryListItem(item))
		endpointIDs = append(endpointIDs, item.EndpointID)
		if asOf.IsZero() || updatedAt.Before(asOf) {
			asOf = updatedAt
		}
	}
	if err = rows.Err(); err != nil {
		return DeviceInventoryListPage{}, err
	}
	rows.Close()
	inventoryTiming(ctx, "page", started)

	started = time.Now()
	matches, err := s.deviceIPMatchesWith(ctx, conn, endpointIDs, query, now)
	if err != nil {
		return DeviceInventoryListPage{}, err
	}
	for index := range items {
		if match := matches[items[index].EndpointID]; match != nil {
			match.IsRecentIP = net.ParseIP(match.IP).Equal(net.ParseIP(items[index].CurrentIP))
			items[index].IPMatch = match
		}
	}
	inventoryTiming(ctx, "ip_match", started)
	var next *string
	if hasNext || query.Cursor+len(items) < total {
		value := strconvArg(query.Cursor + len(items))
		next = &value
	}
	page := Page{Limit: limit, NextCursor: next, Total: total}
	result := DeviceInventoryListPage{Items: items, Page: page, Facets: facets}
	started = time.Now()
	result.ReadModelUpdating, err = s.deviceInventoryUpdating(ctx, conn)
	if err != nil {
		return DeviceInventoryListPage{}, err
	}
	inventoryTiming(ctx, "read_model", started)
	if !asOf.IsZero() {
		result.AsOf = asOf.UTC().Format(time.RFC3339Nano)
	}
	return result, nil
}

type inventoryStatusCache struct {
	mu        sync.Mutex
	expiresAt time.Time
	updating  bool
}

func (s *PostgresStore) deviceInventoryUpdating(ctx context.Context, conn *sql.Conn) (bool, error) {
	s.inventoryStatus.mu.Lock()
	defer s.inventoryStatus.mu.Unlock()
	if time.Now().Before(s.inventoryStatus.expiresAt) {
		return s.inventoryStatus.updating, nil
	}
	statusSQL := `SELECT
 EXISTS(SELECT 1 FROM endpoint_recognition_jobs WHERE processed_generation<dirty_generation LIMIT 1)
 OR EXISTS(SELECT 1 FROM endpoint_entities e LEFT JOIN endpoint_recognition_summary r USING(endpoint_id)
	           WHERE e.entity_role='endpoint' AND r.endpoint_id IS NULL LIMIT 1)`
	var updating bool
	if err := conn.QueryRowContext(ctx, statusSQL).Scan(&updating); err != nil {
		return false, err
	}
	s.inventoryStatus.updating = updating
	s.inventoryStatus.expiresAt = time.Now().Add(5 * time.Second)
	return updating, nil
}
