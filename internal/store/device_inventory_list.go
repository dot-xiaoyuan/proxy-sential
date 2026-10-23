package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ListDeviceInventory reads the prepared endpoint summary projection. It does
// not load endpoint association histories; those belong to the detail path.
func (s *PostgresStore) ListDeviceInventory(ctx context.Context, query Query) (DeviceInventoryListPage, error) {
	if err := normalizeInventorySearch(&query); err != nil {
		return DeviceInventoryListPage{}, err
	}
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
	state, err := inventoryProjectionState(ctx, conn)
	if err != nil {
		return DeviceInventoryListPage{}, err
	}
	if !state.Complete && !state.Available {
		return DeviceInventoryListPage{}, ErrInventoryNotReady
	}

	baseWhere := []string{"e.entity_role='endpoint'"}
	baseArgs := []any{}
	if query.View == "recent" {
		baseArgs = append(baseArgs, deviceViewStart(query, now), now)
		baseWhere = append(baseWhere, "i.last_seen >= $1 AND i.last_seen <= $2")
	}
	position, err := decodeInventoryCursor(query, query.InventoryCursor)
	if err != nil {
		return DeviceInventoryListPage{}, err
	}
	if position != nil {
		if position.LastSeen == "" {
			baseWhere = append(baseWhere, "i.last_seen IS NULL AND i.endpoint_id > $"+strconvArg(len(baseArgs)+1))
			baseArgs = append(baseArgs, position.Endpoint)
		} else {
			lastSeen, parseErr := time.Parse(time.RFC3339Nano, position.LastSeen)
			if parseErr != nil {
				return DeviceInventoryListPage{}, fmt.Errorf("invalid inventory cursor timestamp")
			}
			baseArgs = append(baseArgs, lastSeen, position.Endpoint)
			lastArg, endpointArg := "$"+strconvArg(len(baseArgs)-1), "$"+strconvArg(len(baseArgs))
			baseWhere = append(baseWhere, "(i.last_seen < "+lastArg+" OR (i.last_seen = "+lastArg+" AND i.endpoint_id > "+endpointArg+") OR i.last_seen IS NULL)")
		}
	}
	baseSQL := " FROM endpoint_inventory_lookup i JOIN endpoint_entities e USING(endpoint_id) LEFT JOIN endpoint_recognition_summary r USING(endpoint_id) WHERE " + strings.Join(baseWhere, " AND ")

	facets := DeviceFilterFacets{Brands: []string{}, OSFamilies: []string{}}
	if !query.InventorySkipMetadata {
		started = time.Now()
		facetRows, err := conn.QueryContext(ctx, "SELECT DISTINCT coalesce(r.filter_brand,'unknown'),coalesce(r.filter_os_family,'unknown')"+baseSQL, baseArgs...)
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
		historyWindow, sessionWindow, snapshotWindow := "", "", ""
		if query.View == "recent" {
			args = append(args, deviceViewStart(query, now), now)
			startArg, endArg := "$"+strconvArg(len(args)-1), "$"+strconvArg(len(args))
			historyWindow = " AND h.observed_at >= " + startArg + " AND h.observed_at <= " + endArg
			sessionWindow = " AND s.started_at <= " + endArg + " AND (s.ended_at IS NULL OR s.ended_at >= " + startArg + ")"
			snapshotWindow = " AND " + projectionConfirmedSQL + " BETWEEN " + startArg + " AND " + endArg
		}
		// Start snapshot matches at the indexed current-IP lookup, then check each
		// candidate's current source scope. LIMIT keeps the lateral probe bounded and
		// prevents an IP-wide scan of the large snapshot projection. The parameter
		// is inet in the other branches; host converts it to bare IP text for
		// projection matching without casting the indexed text column.
		where = append(where, `i.endpoint_id IN(SELECT h.endpoint_id FROM device_address_leases h WHERE h.ip=`+ipArg+`::inet AND h.endpoint_id<>''`+historyWindow+` UNION SELECT s.endpoint_id FROM account_sessions s WHERE s.ip=`+ipArg+`::inet AND s.endpoint_id<>''`+sessionWindow+` UNION SELECT candidate.endpoint_id FROM endpoint_inventory_lookup candidate JOIN LATERAL (SELECT 1 FROM account_identity_session_projection p JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain) WHERE p.document->>'endpoint_id'=candidate.endpoint_id AND p.ip=host(`+ipArg+`::inet) AND COALESCE(p.document->>'ended_at','')='' AND `+projectionCurrentSQL+snapshotWindow+` LIMIT 1) snapshot ON true WHERE candidate.current_ip=`+ipArg+`::inet)`)
	}
	if query.Brand != "" {
		if query.Brand == "unknown" {
			add("lower(coalesce(nullif(r.filter_brand,''),'unknown'))=lower($N)", query.Brand)
		} else {
			add("lower(r.filter_brand)=lower($N)", query.Brand)
		}
	}
	if query.OSFamily != "" {
		if query.OSFamily == "unknown" {
			add("lower(coalesce(nullif(r.filter_os_family,''),'unknown'))=lower($N)", query.OSFamily)
		} else {
			add("lower(r.filter_os_family)=lower($N)", query.OSFamily)
		}
	}
	if query.Ecosystem != "" {
		add("lower(r.ecosystem_hint)=lower($N)", query.Ecosystem)
	}
	if ip := net.ParseIP(strings.TrimSpace(query.SrcIP)); ip != nil {
		addExactIP(ip.String())
	}
	if ip := net.ParseIP(strings.TrimSpace(query.Q)); ip != nil && (query.InventorySearchType == "all" || query.InventorySearchType == "ip") {
		addExactIP(ip.String())
	} else if value := strings.TrimSpace(query.Q); value != "" {
		switch query.InventorySearchType {
		case "account":
			add(`i.endpoint_id IN(SELECT endpoint_id FROM endpoint_inventory_accounts WHERE account_id=$N)`, value)
		case "mac":
			add(`i.mac_key=$N`, value)
		case "name":
			add(`lower(i.device_name) LIKE $N ESCAPE '\'`, "%"+inventoryLikeValue(value)+"%")
		default:
			add(`i.search_text LIKE $N ESCAPE '\'`, "%"+inventoryLikeValue(value)+"%")
		}
	}
	for _, dimension := range []struct{ column, value string }{
		{"campus_id", query.CampusID}, {"department", query.Department}, {"person_type", query.PersonType},
		{"ssid", query.SSID}, {"vlan", query.VLAN}, {"ap", query.AP}, {"nas_ip", query.NASIP},
	} {
		if dimension.value == "" {
			continue
		}
		add("i.dimensions @> jsonb_build_object('"+dimension.column+"',$N::text)", dimension.value)
	}

	whereSQL := " FROM endpoint_inventory_lookup i JOIN endpoint_entities e USING(endpoint_id) LEFT JOIN endpoint_recognition_summary r USING(endpoint_id) WHERE " + strings.Join(where, " AND ")
	var total int
	if !query.InventorySkipMetadata {
		started = time.Now()
		if err = conn.QueryRowContext(ctx, "SELECT count(*)"+whereSQL, args...).Scan(&total); err != nil {
			return DeviceInventoryListPage{}, err
		}
		inventoryTiming(ctx, "count", started)
	}
	if query.InventoryMetadataOnly {
		return DeviceInventoryListPage{ReadModelState: &state, Items: []DeviceInventoryListItem{}, Page: Page{Total: total}, Facets: facets, AsOf: now.Format(time.RFC3339Nano)}, nil
	}
	pageLimit := limit
	if query.InventorySkipMetadata {
		pageLimit++
	}
	pageArgs := append(append([]any{}, args...), pageLimit)
	legacyOffset := query.InventoryCursor == ""
	if legacyOffset {
		pageArgs = append(pageArgs, query.Cursor)
	}
	limitArg := strconvArg(len(args) + 1)
	offsetSQL := ""
	if legacyOffset {
		offsetSQL = " OFFSET $" + strconvArg(len(pageArgs))
	}
	started = time.Now()
	rows, err := conn.QueryContext(ctx, `SELECT i.list_item,i.updated_at`+whereSQL+`
ORDER BY i.last_seen DESC NULLS LAST,i.endpoint_id
LIMIT $`+limitArg+offsetSQL, pageArgs...)
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
	matches, err := inventoryIPMatches(ctx, conn, endpointIDs, query, now)
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
	if hasNext && len(items) > 0 {
		last := items[len(items)-1]
		var lastSeen *time.Time
		if last.LastSeen != "" {
			parsed, parseErr := time.Parse(time.RFC3339Nano, last.LastSeen)
			if parseErr != nil {
				return DeviceInventoryListPage{}, parseErr
			}
			lastSeen = &parsed
		}
		value, cursorErr := encodeInventoryCursor(query, lastSeen, last.EndpointID)
		if cursorErr != nil {
			return DeviceInventoryListPage{}, cursorErr
		}
		next = &value
	}
	page := Page{Limit: limit, NextCursor: next, Total: total}
	result := DeviceInventoryListPage{ReadModelState: &state, Items: items, Page: page, Facets: facets}
	started = time.Now()
	result.ReadModelUpdating, err = s.deviceInventoryUpdating(ctx, conn)
	result.ReadModelUpdating = result.ReadModelUpdating || state.Updating
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
