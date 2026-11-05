package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type indexedDeviceCursor struct {
	Version   int    `json:"v"`
	Signature string `json:"s"`
	LastSeen  string `json:"t"`
	DeviceKey string `json:"d"`
}

func indexedDeviceSignature(q DeviceQuery) string {
	b, _ := json.Marshal(struct {
		View, Mode, Search, DeviceType, Category, Capability, Protocol, State, Domain, VLAN string
		Window                                                                              int64
	}{q.View, q.Mode, q.Search, q.DeviceType, q.Category, q.Capability, q.Protocol, q.State, q.Domain, q.VLAN, int64(q.Window)})
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
	if json.Unmarshal(raw, &c) != nil || c.Version != 1 || c.DeviceKey == "" || c.Signature != indexedDeviceSignature(q) {
		return nil, fmt.Errorf("discovery cursor does not match query")
	}
	if _, err = time.Parse(time.RFC3339Nano, c.LastSeen); err != nil {
		return nil, fmt.Errorf("invalid discovery cursor timestamp")
	}
	return &c, nil
}

func encodeIndexedDeviceCursor(q DeviceQuery, item DeviceView) (string, error) {
	raw, err := json.Marshal(indexedDeviceCursor{
		Version: 1, Signature: indexedDeviceSignature(q), LastSeen: item.LastSeen.UTC().Format(time.RFC3339Nano), DeviceKey: item.ID,
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
	if query.Window == 0 || query.Window > 30*24*time.Hour {
		query.Window = 24 * time.Hour
	}
	if query.Limit <= 0 || query.Limit > 200 {
		query.Limit = 50
	}
	if query.Offset != 0 {
		return nil, fmt.Errorf("discovery offset pagination was removed; use cursor")
	}
	if query.View != "" && query.View != "iot" {
		return nil, fmt.Errorf("invalid discovery view")
	}
	position, err := decodeIndexedDeviceCursor(query)
	if err != nil {
		return nil, err
	}
	origins, err := indexedOrigins(query.Mode)
	if err != nil {
		return nil, err
	}
	args := []any{}
	baseWhere := []string{"l.observed_at<=now()", "NOT l.withdrawn"}
	if query.Window > 0 {
		args = append(args, time.Now().UTC().Add(-query.Window))
		baseWhere = append(baseWhere, "l.observed_at>=$1")
	}
	for _, filter := range []struct{ key, value string }{{"domain", query.Domain}, {"vlan", query.VLAN}} {
		if filter.value != "" {
			args = append(args, filter.value)
			baseWhere = append(baseWhere, fmt.Sprintf("coalesce(data->>'%s','')=$%d", filter.key, len(args)))
		}
	}
	if len(origins) > 0 {
		parts := make([]string, len(origins))
		for i, origin := range origins {
			args = append(args, origin)
			parts[i] = fmt.Sprintf("$%d", len(args))
		}
		baseWhere = append(baseWhere, "origin IN ("+strings.Join(parts, ",")+")")
	}
	// Apply service admission before the candidate limit, so newer DHCP-only
	// devices cannot hide a service announcer on a later candidate page.
	if query.View == "iot" {
		baseWhere = append(baseWhere, `origin IN ('dns_sd','ssdp','ws_discovery')`,
			`(data->>'confidence' IN ('strong','confirmed') OR (data->>'confidence'='clue' AND coalesce(data->>'mac','')<>''))`,
			`coalesce(data->'capabilities','[]'::jsonb) ?| ARRAY['printing','scanning','network_video','casting','media_rendering']`)
	}
	having := []string{}
	needle := strings.ToLower(strings.TrimSpace(query.Search))
	exactSearch := false
	if ip := net.ParseIP(needle); ip != nil {
		args = append(args, ip.String())
		having = append(having, "bool_or(lower(coalesce(data->>'ip',''))=$"+fmt.Sprint(len(args))+")")
		exactSearch = true
	} else if mac, e := net.ParseMAC(needle); e == nil {
		args = append(args, strings.ToLower(mac.String()))
		having = append(having, "bool_or(lower(coalesce(data->>'mac',''))=$"+fmt.Sprint(len(args))+")")
		exactSearch = true
	}
	if needle != "" && !exactSearch {
		escaped := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(needle, "\\", "\\\\"), "%", "\\%"), "_", "\\_")
		pattern := "%" + escaped + "%"
		if len([]rune(needle)) < 3 {
			pattern = escaped + "%"
		}
		args = append(args, pattern)
		searchArg := "$" + fmt.Sprint(len(args))
		having = append(having, "bool_or(lower(coalesce(data->>'ip','')) LIKE "+searchArg+" ESCAPE '\\' OR lower(coalesce(data->>'mac','')) LIKE "+searchArg+" ESCAPE '\\' OR lower(coalesce(data->>'name','')) LIKE "+searchArg+" ESCAPE '\\' OR lower(coalesce(data->>'device_type','')) LIKE "+searchArg+" ESCAPE '\\' OR lower(coalesce(data->>'manufacturer','')) LIKE "+searchArg+" ESCAPE '\\' OR lower(coalesce(data->>'model_name','')) LIKE "+searchArg+" ESCAPE '\\')")
	}
	classifiedWhere := []string{}
	if query.DeviceType != "" {
		args = append(args, query.DeviceType)
		classifiedWhere = append(classifiedWhere, fmt.Sprintf("((classification_status='identified' AND effective_types[1]=$%[1]d) OR (classification_status='expired' AND historical_type=$%[1]d))", len(args)))
	}
	if query.Protocol != "" {
		args = append(args, query.Protocol)
		having = append(having, fmt.Sprintf("bool_or(origin=$%d)", len(args)))
	}
	if query.State != "" {
		switch query.State {
		case "identified", "candidate", "expired", "conflict":
		default:
			return nil, fmt.Errorf("invalid discovery state")
		}
		args = append(args, query.State)
		classifiedWhere = append(classifiedWhere, "classification_status=$"+fmt.Sprint(len(args)))
	}
	if query.Capability != "" {
		if query.Capability == "dumb" {
			having = append(having, "bool_or(coalesce(data->'capabilities','[]'::jsonb) ?| ARRAY['printing','scanning','casting','media_rendering','network_video','routing'])")
		} else {
			args = append(args, query.Capability)
			having = append(having, fmt.Sprintf("bool_or(coalesce(data->'capabilities','[]'::jsonb) ? $%d)", len(args)))
		}
	}
	candidateHaving := ""
	if len(having) > 0 {
		candidateHaving = " HAVING " + strings.Join(having, " AND ")
	}

	positionWhere := ""
	if position != nil {
		last, _ := time.Parse(time.RFC3339Nano, position.LastSeen)
		args = append(args, last, position.DeviceKey)
		classifiedWhere = append(classifiedWhere, fmt.Sprintf("(last_seen < $%d OR (last_seen = $%d AND device_key > $%d))", len(args)-1, len(args)-1, len(args)))
	}
	if len(classifiedWhere) > 0 {
		positionWhere = " WHERE " + strings.Join(classifiedWhere, " AND ")
	}
	limitArg := len(args) + 1
	candidateLimit := (query.Limit + 1) * 8
	if candidateLimit < 64 {
		candidateLimit = 64
	}
	if candidateLimit > 2048 {
		candidateLimit = 2048
	}
	args = append(args, candidateLimit)
	statement := `WITH candidate_rows AS (
 SELECT l.*,` + indexedObservationTypeSQL + ` observed_type,
 coalesce(i.endpoint_id,dl.endpoint_id,'') linked_endpoint,
 coalesce(rp.role,'') profile_role,` + indexedProfileConfidenceSQL("rp") + ` profile_confidence,
 CASE WHEN ` + indexedProfileConfidenceSQL("rp") + `>=0.8 AND NOT (` + indexedProfileConflictSQL("rp") + `) THEN coalesce(rp.role,'') ELSE '' END profile_type,
 (` + indexedProfileConflictSQL("rp") + `) AND coalesce(rp.role,'')<>'' profile_conflict
 FROM discovery_observation_latest l
 LEFT JOIN discovery_identity_links i ON i.observation_id=l.id
 LEFT JOIN device_address_leases dl ON dl.event_id=l.id AND dl.action='ack'
 AND dl.sensor_id=coalesce(l.data->>'node','') AND host(dl.ip)=coalesce(l.data->>'ip','')
 AND dl.campus_id=coalesce(l.data->'evidence'->'subject'->>'campus_id','')
 AND dl.endpoint_id='mac:'||lower(coalesce(l.data->>'mac',''))
 LEFT JOIN endpoint_recognition_summary rp ON rp.endpoint_id=coalesce(i.endpoint_id,dl.endpoint_id,'mac:'||lower(coalesce(l.data->>'mac','')))
 WHERE ` + strings.Join(baseWhere, " AND ") + `
), candidate_grouped AS (
 SELECT device_key,max(observed_at) last_seen,
 bool_or(valid_until>now()) is_current,
 bool_or(profile_conflict AND valid_until>now()) type_conflict,
 coalesce(array_agg(observed_type) FILTER (WHERE valid_until>now()),'{}'::text[]) || coalesce(array_agg(profile_type) FILTER (WHERE valid_until>now()),'{}'::text[]) types,
 (array_agg(observed_type ORDER BY observed_at DESC,id) FILTER (WHERE observed_type<>''))[1] historical_type
 FROM candidate_rows
 GROUP BY device_key` + candidateHaving + `
), candidate_types AS (
 SELECT *,` + indexedEffectiveTypesSQL + ` effective_types FROM candidate_grouped
), candidate_source AS (
 SELECT *,` + indexedClassificationStateSQL + ` classification_status FROM candidate_types
), candidates AS (
 SELECT device_key,last_seen FROM candidate_source` + positionWhere + `
 ORDER BY last_seen DESC,device_key
 LIMIT $` + fmt.Sprint(limitArg) + `
)
SELECT l.device_key,l.data,l.linked_endpoint,l.profile_role,l.profile_confidence,l.profile_conflict
FROM candidate_rows l JOIN candidates c USING(device_key)
ORDER BY c.last_seen DESC,l.device_key,l.id`
	rows, err := r.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deviceRows := []deviceObservationRow{}
	candidateTimes := map[string]time.Time{}
	for rows.Next() {
		var key, endpointID, deviceType string
		var confidence float64
		var conflict bool
		var raw []byte
		if err = rows.Scan(&key, &raw, &endpointID, &deviceType, &confidence, &conflict); err != nil {
			return nil, err
		}
		var observation Observation
		if err = json.Unmarshal(raw, &observation); err != nil {
			return nil, err
		}
		if observation.ObservedAt.After(candidateTimes[key]) {
			candidateTimes[key] = observation.ObservedAt
		}
		deviceRows = append(deviceRows, deviceObservationRow{DeviceKey: key, EndpointID: endpointID, ProfileDeviceType: deviceType, ProfileTypeConfidence: confidence, ProfileConflict: conflict, Observation: observation})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	items := aggregateDeviceRows(deviceRows, time.Now().UTC())
	filtered := make([]DeviceView, 0, len(items))
	for _, item := range items {
		if query.DeviceType != "" && item.DeviceType != query.DeviceType && !(item.ClassificationStatus == "expired" && item.LastDeviceType == query.DeviceType) {
			continue
		}
		if query.State != "" && item.ClassificationStatus != query.State {
			continue
		}
		if query.Protocol != "" && !containsString(item.Protocols, query.Protocol) {
			continue
		}
		if query.View == "iot" {
			item.Category = iotServiceCategory(item)
			if item.Category == "" {
				continue
			}
		}
		if query.Category != "" && item.Category != query.Category {
			continue
		}
		if query.Capability != "" && !matchesDeviceCapability(item.Capabilities, query.Capability) {
			continue
		}
		if needle != "" && !exactSearch {
			haystack := strings.ToLower(strings.Join(append(append(append([]string{item.Name, item.MAC, item.DeviceType, item.Manufacturer, item.ModelName}, item.Addresses...), item.Capabilities...), item.Protocols...), " "))
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].LastSeen.Equal(filtered[j].LastSeen) {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].LastSeen.After(filtered[j].LastSeen)
	})
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].ID < items[j].ID
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
	hasMore := len(filtered) > query.Limit
	moreCandidates := len(candidateTimes) >= candidateLimit
	if hasMore {
		filtered = filtered[:query.Limit]
	}
	var nextCursor string
	if hasMore && len(filtered) > 0 {
		nextCursor, err = encodeIndexedDeviceCursor(query, filtered[len(filtered)-1])
		if err != nil {
			return nil, err
		}
	}
	// A bounded candidate page may contain fewer matches than a result page.
	// Keep its continuation instead of incorrectly declaring the dataset empty.
	if !hasMore && moreCandidates {
		hasMore = true
		var lastCandidate DeviceView
		for key, seen := range candidateTimes {
			if lastCandidate.ID == "" || seen.Before(lastCandidate.LastSeen) || (seen.Equal(lastCandidate.LastSeen) && key > lastCandidate.ID) {
				lastCandidate = DeviceView{ID: key, LastSeen: seen}
			}
		}
		nextCursor, err = encodeIndexedDeviceCursor(query, lastCandidate)
		if err != nil {
			return nil, err
		}
	}
	facets := deviceFacets(filtered)
	serviceDevices, linked := 0, 0
	for _, item := range filtered {
		if len(item.Capabilities) > 0 {
			serviceDevices++
		}
		if item.EndpointID != "" {
			linked++
		}
	}
	windowLabel := query.Window.String()
	if query.Window < 0 {
		windowLabel = "all"
	}
	return map[string]any{"items": filtered, "next_cursor": nextCursor, "has_more": hasMore, "facets": facets, "service_devices": serviceDevices, "linked_endpoints": linked, "limit": query.Limit, "window": windowLabel}, nil
}

func indexedOrigins(mode string) ([]string, error) {
	switch mode {
	case "passive":
		return []string{"dhcp", "arp", "ndp", "dns_sd", "ssdp", "ws_discovery", "ieee1905_client"}, nil
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
