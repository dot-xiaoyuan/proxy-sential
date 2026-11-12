package discovery

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type indexedDeviceSelection struct {
	Query DeviceQuery
	CTE   string
	Args  []any
}

// The page and independent count share the same current-index identity groups
// and filters. No historical evidence or unbounded Go result set is read.
func buildIndexedDeviceSelection(query DeviceQuery) (indexedDeviceSelection, error) {
	if query.Window == 0 {
		query.Window = 24 * time.Hour
	} else if query.Window < 0 || query.Window > 30*24*time.Hour {
		query.Window = 30 * 24 * time.Hour
	}
	maxLimit := 200
	if query.Export {
		maxLimit = 1000
	}
	if query.Limit <= 0 || query.Limit > maxLimit {
		query.Limit = 50
	}
	if query.Offset != 0 {
		return indexedDeviceSelection{}, fmt.Errorf("discovery offset pagination was removed; use cursor")
	}
	if query.View != "" && query.View != "iot" {
		return indexedDeviceSelection{}, fmt.Errorf("invalid discovery view")
	}
	reviewPredicate, err := indexedReviewPredicate(query.ReviewReason)
	if query.HardwareV2 {
		reviewPredicate, err = hardwareReviewPredicate(query.ReviewReason)
	}
	if err != nil {
		return indexedDeviceSelection{}, err
	}
	origins, err := indexedOrigins(query.Mode)
	if err != nil {
		return indexedDeviceSelection{}, err
	}
	if query.HardwareV2 && query.Mode == "passive" {
		// A response can keep a trusted hardware identity observable after its
		// address advertisement expires. List, metadata and export share this
		// admission; the 184/default reader retains its original source set.
		origins = append(origins, "snmp", "bacnet", "modbus", "http_device", "rtsp", "sip", "tls_device", "ipp", "onvif")
	}
	args := []any{}
	baseWhere := []string{"l.observed_at<=now()", "NOT l.withdrawn"}
	if query.Window > 0 {
		at := query.SnapshotAt
		if at.IsZero() {
			at = time.Now().UTC()
		}
		args = append(args, at.Add(-query.Window))
		baseWhere = append(baseWhere, "l.observed_at>=$1")
	}
	for _, filter := range []struct{ key, value string }{{"domain", query.Domain}, {"vlan", query.VLAN}} {
		if filter.value != "" {
			args = append(args, filter.value)
			baseWhere = append(baseWhere, fmt.Sprintf("coalesce(data->>'%s','') = ANY(string_to_array($%d, ','))", filter.key, len(args)))
		}
	}
	if query.RandomMAC {
		// Locally administered addresses (second-least-significant bit) rotate,
		// so this cohort needs its own identity handling.
		baseWhere = append(baseWhere, `(CASE WHEN coalesce(l.data->>'mac','') ~ '^[0-9a-fA-F]{2}' THEN ((('x'||substr(l.data->>'mac',1,2))::bit(8)::int) & 2)=2 ELSE false END)`)
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
		having = append(having, "bool_or(coalesce(search_ip,'')=$"+fmt.Sprint(len(args))+")")
		exactSearch = true
	} else if mac, e := net.ParseMAC(needle); e == nil {
		args = append(args, strings.ToLower(mac.String()))
		having = append(having, "bool_or(coalesce(search_mac,'')=$"+fmt.Sprint(len(args))+")")
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
		having = append(having, "bool_or(lower(profile_type) LIKE "+searchArg+" ESCAPE '\\' OR coalesce(search_ip,'') LIKE "+searchArg+" ESCAPE '\\' OR coalesce(search_mac,'') LIKE "+searchArg+" ESCAPE '\\' OR coalesce(search_name,'') LIKE "+searchArg+" ESCAPE '\\' OR coalesce(search_device_type,'') LIKE "+searchArg+" ESCAPE '\\' OR coalesce(search_manufacturer,'') LIKE "+searchArg+" ESCAPE '\\' OR coalesce(search_model,'') LIKE "+searchArg+" ESCAPE '\\')")
	}
	classifiedWhere := []string{}
	if query.DeviceType != "" {
		// Comma-separated types stay parameterized; the indexed path matches any
		// of them against the identified/expired/candidate type columns.
		args = append(args, query.DeviceType)
		match := "= ANY(string_to_array($" + fmt.Sprint(len(args)) + ", ','))"
		if query.HardwareV2 {
			classifiedWhere = append(classifiedWhere, "projection_type"+match)
		} else {
			classifiedWhere = append(classifiedWhere, "((classification_status='identified' AND effective_types[1]"+match+") OR (classification_status='expired' AND historical_type"+match+") OR (classification_status='candidate' AND candidate_role"+match+"))")
		}
	}
	if query.Protocol != "" {
		args = append(args, query.Protocol)
		having = append(having, fmt.Sprintf("bool_or(origin = ANY(string_to_array($%d, ',')))", len(args)))
	}
	if query.State != "" {
		for _, state := range strings.Split(query.State, ",") {
			switch strings.TrimSpace(state) {
			case "identified", "candidate", "expired", "conflict":
			default:
				return indexedDeviceSelection{}, fmt.Errorf("invalid discovery state")
			}
		}
		args = append(args, query.State)
		classifiedWhere = append(classifiedWhere, "classification_status = ANY(string_to_array($"+fmt.Sprint(len(args))+", ','))")
	}
	if query.Capability != "" {
		if query.Capability == "dumb" {
			having = append(having, "bool_or(observation_capabilities ?| ARRAY['printing','scanning','casting','media_rendering','network_video','routing','voice'])")
		} else {
			args = append(args, query.Capability)
			having = append(having, fmt.Sprintf("bool_or(observation_capabilities ? $%d)", len(args)))
		}
	}
	candidateHaving := ""
	if len(having) > 0 {
		candidateHaving = " HAVING " + strings.Join(having, " AND ")
	}

	if query.Category != "" {
		args = append(args, query.Category)
		classifiedWhere = append(classifiedWhere, "category=$"+fmt.Sprint(len(args)))
	}
	if query.OSFamily != "" {
		args = append(args, "%"+strings.ToLower(query.OSFamily)+"%")
		classifiedWhere = append(classifiedWhere, "lower(profile_os) LIKE $"+fmt.Sprint(len(args)))
	}
	if query.HardwareV2 && query.ReviewReason != "" {
		at := query.SnapshotAt
		if at.IsZero() {
			at = time.Now().UTC()
		}
		args = append(args, at)
		reviewPredicate, err = hardwareReviewPredicate(query.ReviewReason, fmt.Sprintf("$%d", len(args)))
		if err != nil {
			return indexedDeviceSelection{}, err
		}
	}
	if reviewPredicate != "" {
		classifiedWhere = append(classifiedWhere, reviewPredicate)
	}
	matchedWhere := ""
	if len(classifiedWhere) > 0 {
		matchedWhere = " WHERE " + strings.Join(classifiedWhere, " AND ")
	}
	deviceKeysSQL := "NULL::text[]"
	if query.ReviewReason == "new_priority" || query.ReviewReason == "type_change" || query.ReviewReason == "address_only" {
		deviceKeysSQL = "array_agg(DISTINCT device_key)"
	}
	addressSourcesSQL := "false"
	if query.ReviewReason == "address_only" {
		addressSourcesSQL = "bool_and(origin IN ('arp','ndp'))"
	}
	statement := `WITH trusted_address AS MATERIALIZED (
 SELECT m.id observation_id,t.mac FROM discovery_observation_latest m
 JOIN LATERAL (
  SELECT min(lower(v.data->>'mac')) mac FROM discovery_observation_latest v
  WHERE v.data->>'ip'=m.data->>'ip' AND v.observed_at<=now() AND v.valid_until>now() AND NOT v.withdrawn
   AND coalesce(v.data->>'mac','')<>''
   AND coalesce(v.data->>'node','')=coalesce(m.data->>'node','')
   AND coalesce(v.data->>'site','')=coalesce(m.data->>'site','')
   AND coalesce(v.data->>'domain','')=coalesce(m.data->>'domain','')
   AND coalesce(v.data->>'vlan','')=coalesce(m.data->>'vlan','')
   AND coalesce(v.data->>'vrf','')=coalesce(m.data->>'vrf','')
   AND (v.origin IN ('arp','ndp','dhcp') OR (v.origin='sadp' AND v.data->'evidence'->'payload'->>'identity_status' IN ('direct_l2','arp_binding')))
  HAVING count(DISTINCT lower(v.data->>'mac'))=1
   AND bool_or(v.origin='arp' OR (v.origin='sadp' AND v.data->'evidence'->'payload'->>'identity_status' IN ('direct_l2','arp_binding')))
 ) t ON lower(coalesce(m.data->'evidence'->'payload'->>'claimed_mac',''))=t.mac
 WHERE m.origin='sadp' AND NOT m.withdrawn AND m.observed_at<=now() AND m.observed_at>=now()-interval '30 days'
  AND coalesce(m.data->>'node','')<>'' AND coalesce(m.data->>'site','')<>'' AND coalesce(m.data->>'domain','')<>''
  AND coalesce(m.data->>'mac','')='' AND m.data->'evidence'->'payload'->>'identity_status'='l2_mismatch'
  AND m.data->'evidence'->'payload'->>'claimed_ip'=m.data->>'ip'
), link_exceptions AS MATERIALIZED (
 SELECT observation_id,endpoint_id FROM discovery_identity_links
 WHERE coalesce(basis->>'mac','')='' OR lower(endpoint_id)<>'mac:'||lower(basis->>'mac')
), candidate_links AS (
 SELECT l.id,l.device_key,l.origin,l.observed_at,l.valid_until,l.data,
 coalesce(i.endpoint_id,ix.endpoint_id,dl.endpoint_id) linked_endpoint
 FROM discovery_observation_latest l
 -- Most MAC links repeat the observed MAC. Only look up missing-MAC links
 -- and explicit identity exceptions in the large historical link table.
 LEFT JOIN LATERAL (
  SELECT endpoint_id FROM discovery_identity_links
  WHERE observation_id=l.id AND coalesce(l.data->>'mac','')=''
  LIMIT 1
 ) i ON true
 LEFT JOIN link_exceptions ix ON ix.observation_id=l.id
 LEFT JOIN device_address_leases dl ON dl.event_id=l.id AND dl.action='ack'
 AND dl.sensor_id=coalesce(l.data->>'node','') AND host(dl.ip)=coalesce(l.data->>'ip','')
 AND dl.campus_id=coalesce(l.data->'evidence'->'subject'->>'campus_id','')
 AND dl.endpoint_id='mac:'||lower(coalesce(l.data->>'mac',''))
 WHERE ` + strings.Join(baseWhere, " AND ") + `
), display_links AS MATERIALIZED (
 SELECT l.*,
 CASE WHEN t.mac IS NOT NULL
  THEN 'mac:'||t.mac ELSE l.linked_endpoint END display_endpoint
 FROM candidate_links l LEFT JOIN trusted_address t ON t.observation_id=l.id
), recognition AS MATERIALIZED (
 SELECT rec.endpoint_id,
  coalesce(rec.role,'') role,
  coalesce(rec.os_family,'') os_family,
  coalesce(NULLIF(rec.summary->>'device_type_confidence','')::double precision,rec.confidence,0) profile_confidence,
  CASE WHEN jsonb_array_length(coalesce(rec.summary->'conflict_dimensions','[]'::jsonb))>0
   THEN rec.summary->'conflict_dimensions' ? 'device_type'
   ELSE coalesce(rec.conflict,false) END profile_conflict
 FROM endpoint_recognition_summary rec
 JOIN (SELECT DISTINCT coalesce(display_endpoint,'mac:'||lower(coalesce(data->>'mac',''))) endpoint_id
       FROM display_links) active ON active.endpoint_id=rec.endpoint_id
), candidate_rows AS (
 SELECT l.id,l.device_key,l.origin,l.observed_at,l.valid_until,l.data,lower(coalesce(l.data->>'ip','')) search_ip,lower(coalesce(l.data->>'mac','')) search_mac,lower(coalesce(l.data->>'name','')) search_name,lower(coalesce(l.data->>'device_type','')) search_device_type,lower(coalesce(l.data->>'manufacturer','')) search_manufacturer,lower(coalesce(l.data->>'model_name','')) search_model,` + indexedIdentitySQL + ` identity_key,` + indexedObservationCapabilitiesSQL + ` observation_capabilities,` + indexedObservationTypeSQL + ` observed_type,
 coalesce(l.display_endpoint,'') linked_endpoint,
 coalesce(rec.role,'') profile_role,coalesce(rec.profile_confidence,0) profile_confidence,coalesce(rec.os_family,'') profile_os,
 CASE WHEN coalesce(rec.profile_confidence,0)>=0.8 AND NOT (coalesce(rec.profile_conflict,false)) THEN coalesce(rec.role,'') ELSE '' END profile_type,
 (coalesce(rec.profile_conflict,false)) AND coalesce(rec.role,'')<>'' profile_conflict,
 CASE WHEN NOT (coalesce(rec.profile_conflict,false)) AND coalesce(rec.profile_confidence,0)>=0.4 AND coalesce(rec.profile_confidence,0)<0.8 THEN coalesce(rec.role,'') ELSE '' END profile_candidate_role
 FROM display_links l
 LEFT JOIN recognition rec ON rec.endpoint_id=coalesce(l.display_endpoint,'mac:'||lower(coalesce(l.data->>'mac','')))
), candidate_grouped AS (
 SELECT identity_key,coalesce(min(device_key COLLATE "C") FILTER (WHERE coalesce(data->>'mac','')<>''),min(device_key COLLATE "C")) device_key,` + deviceKeysSQL + ` device_keys,max(observed_at) last_seen,
 max(profile_os) profile_os,
 bool_or(observation_capabilities ?| ARRAY['printing','scanning']) has_printing,
 bool_or(observation_capabilities ? 'network_video') has_video,
 bool_or(observation_capabilities ?| ARRAY['casting','media_rendering']) has_media,
 bool_or(valid_until>now()) is_current,
 ` + addressSourcesSQL + ` only_address_sources,
 bool_or(profile_conflict AND valid_until>now()) type_conflict,
 coalesce(array_agg(observed_type) FILTER (WHERE valid_until>now()),'{}'::text[]) || coalesce(array_agg(profile_type) FILTER (WHERE valid_until>now()),'{}'::text[]) types,
 (array_agg(observed_type ORDER BY observed_at DESC,id) FILTER (WHERE observed_type<>''))[1] historical_type,
 CASE WHEN count(DISTINCT profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'')=1
  THEN min(profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'')
  ELSE '' END candidate_role
 FROM candidate_rows
 GROUP BY identity_key` + candidateHaving + `
), candidate_types AS (
 ` + indexedTypesProjection(query.HardwareV2) + `
), candidate_classified AS (
 SELECT *,` + indexedClassificationProjection(query.HardwareV2) + ` classification_status FROM candidate_types
), candidate_source AS (
 SELECT *,` + indexedCategorySQL(query.View) + ` category FROM candidate_classified
), matched AS (
 SELECT * FROM candidate_source` + matchedWhere + `
)`
	return indexedDeviceSelection{Query: query, CTE: statement, Args: args}, nil
}

// Each history probe is scoped to a current identity's indexed device keys.
// It never joins or groups the full historical observation table in a list read.
func indexedReviewPredicate(reason string) (string, error) {
	switch reason {
	case "":
		return "", nil
	case "conflict":
		return "classification_status='conflict'", nil
	case "new_priority":
		return `classification_status='identified' AND effective_types[1] IN ('printer','camera','recorder','access_control','voip_phone')
 AND NOT EXISTS (SELECT 1 FROM unnest(device_keys) AS dk(device_key) JOIN LATERAL
	 (SELECT h.observed_at FROM discovery_observations h WHERE h.device_key=dk.device_key
	  ORDER BY h.observed_at ASC LIMIT 1) first_observation ON true
	 WHERE first_observation.observed_at<now()-interval '7 days')`, nil
	case "type_change":
		return `classification_status='identified' AND EXISTS (
 SELECT 1 FROM unnest(device_keys) AS dk(device_key) JOIN LATERAL (
  SELECT 1 FROM discovery_observations h
  WHERE h.device_key=dk.device_key AND h.observed_at>=now()-interval '7 days'
    AND h.observed_at<last_seen AND h.valid_until>h.observed_at
    AND h.data->>'confidence' IN ('strong','confirmed')
    AND coalesce(h.data->>'device_type','')<>''
    AND h.data->>'device_type'<>effective_types[1]
  LIMIT 1
 ) old ON true)`, nil
	case "address_only":
		return `classification_status='candidate' AND only_address_sources AND cardinality(effective_types)=0 AND candidate_role=''
 AND EXISTS (SELECT 1 FROM unnest(device_keys) AS dk(device_key) JOIN LATERAL
	 (SELECT h.observed_at FROM discovery_observations h WHERE h.device_key=dk.device_key
	  AND h.origin IN ('arp','ndp') ORDER BY h.observed_at ASC LIMIT 1) first_address ON true
	 WHERE first_address.observed_at<=now()-interval '7 days')
 AND NOT EXISTS (SELECT 1 FROM unnest(device_keys) AS dk(device_key)
  JOIN discovery_observation_latest other ON other.device_key=dk.device_key
  WHERE other.origin NOT IN ('arp','ndp') AND other.observed_at>=now()-interval '7 days')`, nil
	default:
		return "", fmt.Errorf("invalid discovery review reason")
	}
}
