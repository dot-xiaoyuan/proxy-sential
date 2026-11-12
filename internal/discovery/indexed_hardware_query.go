package discovery

import "strings"

// Hardware classification already has an incremental authoritative projection.
// Keep only scalar search/identity fields before pagination; the same statement
// fetches the selected original rows by their MVCC tuple locator afterward.
// No ctid is persisted, exported, or used across statements/snapshots.
func buildHardwareIndexedSelection(query DeviceQuery, args []any, baseWhere []string, candidateHaving, matchedWhere string) indexedDeviceSelection {
	searchIP, searchName, searchType, searchManufacturer, searchModel := "''::text", "''::text", "''::text", "''::text", "''::text"
	profileType := "''::text"
	if query.Search != "" {
		searchIP = "lower(coalesce(l.data->>'ip',''))"
		searchName = "lower(coalesce(l.data->>'name',''))"
		searchType = "lower(coalesce(l.data->>'device_type',''))"
		searchManufacturer = "lower(coalesce(l.data->>'manufacturer',''))"
		searchModel = "lower(coalesce(l.data->>'model_name',''))"
		profileType = "CASE WHEN coalesce(rec.profile_confidence,0)>=0.8 AND NOT coalesce(rec.profile_conflict,false) THEN coalesce(rec.role,'') ELSE '' END"
	}
	caps := "'[]'::jsonb"
	if query.Capability != "" || query.View == "iot" {
		caps = indexedObservationCapabilitiesSQL
	}
	identitySQL := strings.NewReplacer(
		"coalesce(l.data->>'mac','')", "l.raw_mac", "l.data->>'mac'", "l.raw_mac",
		"coalesce(l.data->>'node','')", "l.sensor_id", "coalesce(l.data->>'site','')", "l.site_id",
		"coalesce(l.data->>'domain','')", "l.access_domain", "coalesce(l.data->>'vlan','')", "l.vlan",
		"coalesce(l.data->>'vrf','')", "l.vrf",
	).Replace(indexedIdentitySQL)
	profileOS := "''::text"
	if query.OSFamily != "" {
		profileOS = "coalesce(rec.os_family,'')"
	}
	pageProfiles := query.Search == "" && query.Category == "" && query.OSFamily == ""
	recognitionSource := `SELECT rec.endpoint_id,coalesce(rec.role,'') role,coalesce(rec.os_family,'') os_family,
 ` + indexedProfileConfidenceSQL("rec") + ` profile_confidence,
 ` + indexedProfileConflictSQL("rec") + ` profile_conflict
 FROM endpoint_recognition_summary rec
 JOIN (SELECT DISTINCT recognition_endpoint COLLATE "C" recognition_endpoint FROM seed_rows) relevant ON relevant.recognition_endpoint=rec.endpoint_id`
	if pageProfiles {
		// These clues do not select identities for this query. Parse them only
		// for the selected page; metadata only counts hardware states/types.
		recognitionSource = `SELECT ''::text endpoint_id,''::text role,''::text os_family,0::double precision profile_confidence,false profile_conflict WHERE false`
	}
	statement := `WITH trusted_address AS MATERIALIZED (
 SELECT m.id observation_id,t.mac FROM discovery_observation_latest m
 JOIN LATERAL (
  SELECT min(lower(v.data->>'mac')) mac FROM discovery_observation_latest v
  WHERE coalesce(v.data->>'ip','')<>'' AND v.data->>'ip'=m.data->>'ip' AND v.observed_at<=now() AND v.valid_until>now() AND NOT v.withdrawn
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
), source_rows AS MATERIALIZED (
 SELECT l.ctid observation_tid,l.id,l.device_key,l.origin,l.observed_at,l.valid_until,
 coalesce(l.data->>'node','') sensor_id,coalesce(l.data->>'site','') site_id,
 coalesce(l.data->>'domain','') access_domain,coalesce(l.data->>'vlan','') vlan,coalesce(l.data->>'vrf','') vrf,
 coalesce(l.data->>'mac','') raw_mac,coalesce(l.data->>'ip','') raw_ip,
 coalesce(l.data->'evidence'->'subject'->>'campus_id','') source_campus,
 ` + searchIP + ` search_ip,lower(coalesce(l.data->>'mac','')) search_mac,
 ` + searchName + ` search_name,` + searchType + ` search_device_type,
 ` + searchManufacturer + ` search_manufacturer,` + searchModel + ` search_model,
 ` + caps + ` observation_capabilities
 FROM discovery_observation_latest l WHERE ` + strings.Join(baseWhere, " AND ") + `
), missing_mac_links AS MATERIALIZED (
 SELECT observation_id,endpoint_id FROM discovery_identity_links
 WHERE observation_id=ANY(ARRAY(SELECT id FROM source_rows WHERE raw_mac=''))
), candidate_links AS NOT MATERIALIZED (
 SELECT l.*,coalesce(i.endpoint_id,ix.endpoint_id,dl.endpoint_id) linked_endpoint
 FROM source_rows l
 LEFT JOIN missing_mac_links i ON i.observation_id=l.id AND l.raw_mac='' 
 LEFT JOIN link_exceptions ix ON ix.observation_id=l.id
 LEFT JOIN device_address_leases dl ON dl.event_id=l.id AND dl.action='ack'
 AND dl.sensor_id=l.sensor_id AND host(dl.ip)=l.raw_ip
 AND dl.campus_id=l.source_campus AND dl.endpoint_id='mac:'||lower(l.raw_mac)
), display_links AS NOT MATERIALIZED (
 SELECT l.*,CASE WHEN t.mac IS NOT NULL THEN 'mac:'||t.mac ELSE l.linked_endpoint END display_endpoint
 FROM candidate_links l LEFT JOIN trusted_address t ON t.observation_id=l.id
), seed_rows AS MATERIALIZED (
 SELECT l.observation_tid,l.id,l.device_key,l.origin,l.observed_at,l.valid_until,
 l.search_ip,l.search_mac,l.search_name,l.search_device_type,l.search_manufacturer,l.search_model,
 ` + identitySQL + ` identity_key,l.observation_capabilities,
 coalesce(l.display_endpoint,'') linked_endpoint,
 coalesce(l.display_endpoint,'mac:'||lower(l.raw_mac)) recognition_endpoint
 FROM display_links l
), recognition AS MATERIALIZED (
 ` + recognitionSource + `
), candidate_rows AS MATERIALIZED (
 SELECT l.observation_tid,l.id,l.device_key,l.origin,l.observed_at,l.valid_until,
 l.search_ip,l.search_mac,l.search_name,l.search_device_type,l.search_manufacturer,l.search_model,
 l.identity_key,l.observation_capabilities,l.linked_endpoint,l.recognition_endpoint,
 coalesce(rec.role,'') profile_role,coalesce(rec.profile_confidence,0) profile_confidence,
 ` + profileOS + ` profile_os,` + profileType + ` profile_type,
 coalesce(rec.profile_conflict,false) AND coalesce(rec.role,'')<>'' profile_conflict,
 CASE WHEN NOT coalesce(rec.profile_conflict,false) AND coalesce(rec.profile_confidence,0)>=0.4 AND coalesce(rec.profile_confidence,0)<0.8 THEN coalesce(rec.role,'') ELSE '' END profile_candidate_role
 FROM seed_rows l LEFT JOIN recognition rec ON rec.endpoint_id=l.recognition_endpoint
), candidate_grouped AS (
 SELECT identity_key COLLATE "C" identity_key,coalesce(min(device_key COLLATE "C") FILTER (WHERE search_mac<>''),min(device_key COLLATE "C")) device_key,
 max(observed_at) last_seen,max(profile_os) profile_os,
 bool_or(observation_capabilities ?| ARRAY['printing','scanning']) has_printing,
 bool_or(observation_capabilities ? 'network_video') has_video,
 bool_or(observation_capabilities ?| ARRAY['casting','media_rendering']) has_media,
 CASE WHEN count(DISTINCT profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'')=1
 THEN min(profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'') ELSE '' END candidate_role
 FROM candidate_rows GROUP BY identity_key COLLATE "C"` + candidateHaving + `
), candidate_types AS (
 ` + indexedTypesProjection(true) + `
), candidate_classified AS (
 SELECT *,` + indexedClassificationProjection(true) + ` classification_status FROM candidate_types
), candidate_source AS (
 SELECT *,` + indexedCategorySQL(query.View) + ` category FROM candidate_classified
), matched AS (
 SELECT * FROM candidate_source` + matchedWhere + `
)`
	return indexedDeviceSelection{Query: query, CTE: statement, Args: args, PageProfiles: pageProfiles}
}

// Fetch documents only after the bounded identity page. The locator is used
// solely in this statement's MVCC snapshot. Common MAC links were already
// coalesced in seed_rows: the legacy page_link CASE fallback was unreachable,
// so probing the historical link table here would only add random disk reads.
func buildHardwareIndexedPage(selection indexedDeviceSelection, positionWhere, limitParameter string) string {
	profiles := "l.profile_role,l.profile_confidence,l.profile_conflict"
	profileJoin := ""
	if selection.PageProfiles {
		profiles = "coalesce(page_rec.role,'')," + indexedProfileConfidenceSQL("page_rec") + ",(" + indexedProfileConflictSQL("page_rec") + ") AND coalesce(page_rec.role,'')<>''"
		profileJoin = "LEFT JOIN endpoint_recognition_summary page_rec ON page_rec.endpoint_id=l.recognition_endpoint\n"
	}
	return selection.CTE + `, candidates AS (
 SELECT identity_key,device_key,last_seen,category FROM matched` + positionWhere + `
 ORDER BY last_seen DESC,identity_key COLLATE "C" LIMIT $` + limitParameter + `
)
SELECT c.identity_key,c.device_key,page_o.data,l.linked_endpoint,` + profiles + `,c.category
FROM candidate_rows l JOIN candidates c USING(identity_key)
JOIN discovery_observation_latest page_o ON page_o.ctid=l.observation_tid
` + profileJoin + `ORDER BY c.last_seen DESC,c.identity_key COLLATE "C",l.id`
}
