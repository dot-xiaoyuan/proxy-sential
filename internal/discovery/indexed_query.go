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
	if query.Limit <= 0 || query.Limit > 200 {
		query.Limit = 50
	}
	if query.Offset != 0 {
		return indexedDeviceSelection{}, fmt.Errorf("discovery offset pagination was removed; use cursor")
	}
	if query.View != "" && query.View != "iot" {
		return indexedDeviceSelection{}, fmt.Errorf("invalid discovery view")
	}
	origins, err := indexedOrigins(query.Mode)
	if err != nil {
		return indexedDeviceSelection{}, err
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
		args = append(args, query.DeviceType)
		classifiedWhere = append(classifiedWhere, fmt.Sprintf("((classification_status='identified' AND effective_types[1]=$%[1]d) OR (classification_status='expired' AND historical_type=$%[1]d) OR (classification_status='candidate' AND candidate_role=$%[1]d))", len(args)))
	}
	if query.Protocol != "" {
		args = append(args, query.Protocol)
		having = append(having, fmt.Sprintf("bool_or(origin=$%d)", len(args)))
	}
	if query.State != "" {
		switch query.State {
		case "identified", "candidate", "expired", "conflict":
		default:
			return indexedDeviceSelection{}, fmt.Errorf("invalid discovery state")
		}
		args = append(args, query.State)
		classifiedWhere = append(classifiedWhere, "classification_status=$"+fmt.Sprint(len(args)))
	}
	if query.Capability != "" {
		if query.Capability == "dumb" {
			having = append(having, "bool_or(observation_capabilities ?| ARRAY['printing','scanning','casting','media_rendering','network_video','routing'])")
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
	matchedWhere := ""
	if len(classifiedWhere) > 0 {
		matchedWhere = " WHERE " + strings.Join(classifiedWhere, " AND ")
	}
	statement := `WITH recognition AS MATERIALIZED (
 SELECT endpoint_id,
  coalesce(role,'') role,
  coalesce(NULLIF(summary->>'device_type_confidence','')::double precision,confidence,0) profile_confidence,
  CASE WHEN jsonb_array_length(coalesce(summary->'conflict_dimensions','[]'::jsonb))>0
   THEN summary->'conflict_dimensions' ? 'device_type'
   ELSE coalesce(conflict,false) END profile_conflict
 FROM endpoint_recognition_summary
), candidate_rows AS (
 SELECT l.id,l.device_key,l.observed_at,l.valid_until,lower(coalesce(l.data->>'ip','')) search_ip,lower(coalesce(l.data->>'mac','')) search_mac,lower(coalesce(l.data->>'name','')) search_name,lower(coalesce(l.data->>'device_type','')) search_device_type,lower(coalesce(l.data->>'manufacturer','')) search_manufacturer,lower(coalesce(l.data->>'model_name','')) search_model,` + indexedIdentitySQL + ` identity_key,` + indexedObservationCapabilitiesSQL + ` observation_capabilities,` + indexedObservationTypeSQL + ` observed_type,
 coalesce(i.endpoint_id,ix.endpoint_id,dl.endpoint_id,'') linked_endpoint,
 coalesce(rec.role,'') profile_role,coalesce(rec.profile_confidence,0) profile_confidence,
 CASE WHEN coalesce(rec.profile_confidence,0)>=0.8 AND NOT (coalesce(rec.profile_conflict,false)) THEN coalesce(rec.role,'') ELSE '' END profile_type,
 (coalesce(rec.profile_conflict,false)) AND coalesce(rec.role,'')<>'' profile_conflict,
 CASE WHEN NOT (coalesce(rec.profile_conflict,false)) AND coalesce(rec.profile_confidence,0)>=0.4 AND coalesce(rec.profile_confidence,0)<0.8 THEN coalesce(rec.role,'') ELSE '' END profile_candidate_role
 FROM discovery_observation_latest l
 -- MAC-matching links add no identity information. Their historical table is
 -- large; inspect it only for observations without a MAC or link exceptions.
 LEFT JOIN LATERAL (
  SELECT endpoint_id FROM discovery_identity_links
  WHERE observation_id=l.id AND coalesce(l.data->>'mac','')=''
  LIMIT 1
 ) i ON true
 LEFT JOIN discovery_identity_links ix ON ix.observation_id=l.id
 AND (coalesce(ix.basis->>'mac','')='' OR lower(ix.endpoint_id)<>'mac:'||lower(ix.basis->>'mac'))
 LEFT JOIN device_address_leases dl ON dl.event_id=l.id AND dl.action='ack'
 AND dl.sensor_id=coalesce(l.data->>'node','') AND host(dl.ip)=coalesce(l.data->>'ip','')
 AND dl.campus_id=coalesce(l.data->'evidence'->'subject'->>'campus_id','')
 AND dl.endpoint_id='mac:'||lower(coalesce(l.data->>'mac',''))
 LEFT JOIN recognition rec ON rec.endpoint_id=coalesce(i.endpoint_id,ix.endpoint_id,dl.endpoint_id,'mac:'||lower(coalesce(l.data->>'mac','')))
 WHERE ` + strings.Join(baseWhere, " AND ") + `
), candidate_grouped AS (
 SELECT identity_key,min(device_key COLLATE "C") device_key,max(observed_at) last_seen,
 bool_or(observation_capabilities ?| ARRAY['printing','scanning']) has_printing,
 bool_or(observation_capabilities ? 'network_video') has_video,
 bool_or(observation_capabilities ?| ARRAY['casting','media_rendering']) has_media,
 bool_or(valid_until>now()) is_current,
 bool_or(profile_conflict AND valid_until>now()) type_conflict,
 coalesce(array_agg(observed_type) FILTER (WHERE valid_until>now()),'{}'::text[]) || coalesce(array_agg(profile_type) FILTER (WHERE valid_until>now()),'{}'::text[]) types,
 (array_agg(observed_type ORDER BY observed_at DESC,id) FILTER (WHERE observed_type<>''))[1] historical_type,
 CASE WHEN count(DISTINCT profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'')=1
  THEN min(profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'')
  ELSE '' END candidate_role
 FROM candidate_rows
 GROUP BY identity_key` + candidateHaving + `
), candidate_types AS (
 SELECT *,` + indexedEffectiveTypesSQL + ` effective_types FROM candidate_grouped
), candidate_classified AS (
 SELECT *,` + indexedClassificationStateSQL + ` classification_status FROM candidate_types
), candidate_source AS (
 SELECT *,` + indexedCategorySQL(query.View) + ` category FROM candidate_classified
), matched AS (
 SELECT * FROM candidate_source` + matchedWhere + `
)`
	return indexedDeviceSelection{Query: query, CTE: statement, Args: args}, nil
}
