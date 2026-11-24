package discovery

import "strings"

func hardwareProfileCandidateSQL(role, confidence, conflict, seen string) string {
	return "CASE WHEN l.profile_identity_verified AND l.valid_until>now() AND " + seen + ">=$1 AND " +
		seen + "<=now() AND " + confidence + ">=0.4 AND NOT " + conflict + " THEN coalesce(" + role + ",'') ELSE '' END"
}

// Hardware classification already has an incremental authoritative projection.
// Keep only scalar search/identity fields before pagination; the same statement
// fetches the selected original rows by their MVCC tuple locator afterward.
// Decode the source JSON once for each admitted row instead of detoasting it
// separately for every scope, search and evidence field.
// Point-lookups keep the historical identity and lease tables out of the
// candidate scan. The observation index still determines the query window.
// No ctid is persisted, exported, or used across statements/snapshots.
func buildHardwareIndexedSelection(query DeviceQuery, args []any, baseWhere []string, candidateHaving, matchedWhere string) indexedDeviceSelection {
	searchIP, searchName, searchType, searchManufacturer, searchModel := "''::text", "''::text", "''::text", "''::text", "''::text"
	dhcpType := "''::text"
	if query.DeviceType != "" || query.includeCandidateTypes || query.View == "iot" || query.Capability == "dumb" {
		dhcpType = `CASE WHEN l.origin IN ('dhcp_client','dhcp') AND NOT l.withdrawn AND l.valid_until>now() THEN coalesce(d.evidence->'payload'->>'dhcp_candidate_type','') ELSE '' END`
	}
	profileType := "''::text"
	if query.Search != "" {
		searchIP = "lower(coalesce(d.ip,''))"
		searchName = "lower(coalesce(d.name,''))"
		searchType = "lower(coalesce(d.device_type,''))"
		searchManufacturer = "lower(coalesce(d.manufacturer,''))"
		searchModel = "lower(coalesce(d.model_name,''))"
		profileType = "CASE WHEN coalesce(rec.profile_confidence,0)>=0.8 AND NOT coalesce(rec.profile_conflict,false) THEN coalesce(rec.role,'') ELSE '' END"
	}
	caps := "'[]'::jsonb"
	if query.Capability != "" || query.View == "iot" {
		caps = strings.NewReplacer("data->>'name'", "d.name", "data->'evidence'", "d.evidence",
			"data->'capabilities'", "d.capabilities").Replace(indexedObservationCapabilitiesSQL)
	}
	productType := "''::text"
	if query.DeviceType != "" || query.includeCandidateTypes || query.View == "iot" || query.Capability == "dumb" {
		productType = indexedValidProductTypeSQL
	}
	productEvidence := "false"
	if query.IdentityScope != "" {
		productEvidence = `coalesce((` + indexedProductAttributionSQL + `
 AND d.product_clue->>'product_status' IN ('identified','no_type_match','conflict')),false)`
	}
	subnet, subnets := "''::text", "'{}'::text[]"
	if query.includeOverview || query.Subnet != "" {
		subnets = `coalesce(array_agg(DISTINCT subnet) FILTER (WHERE subnet<>''),'{}'::text[])`
		// Use only currently valid address facts with directly observed hardware
		// identity. IP-only product and profile clues do not define a subnet.
		subnet = `CASE WHEN l.profile_identity_verified AND l.valid_until>now() AND l.origin IN ('arp','ndp','dhcp')
 AND pg_input_is_valid(l.raw_ip,'inet') THEN
 network(set_masklen(l.raw_ip::inet,CASE family(l.raw_ip::inet) WHEN 4 THEN 24 ELSE 64 END))::text ELSE '' END`
	}
	identitySQL := strings.NewReplacer(
		"coalesce(l.data->>'mac','')", "l.raw_mac", "l.data->>'mac'", "l.raw_mac",
		"coalesce(l.data->>'node','')", "l.sensor_id", "coalesce(l.data->>'site','')", "l.site_id",
		"coalesce(l.data->>'domain','')", "l.access_domain", "coalesce(l.data->>'vlan','')", "l.vlan",
		"coalesce(l.data->>'vrf','')", "l.vrf",
	).Replace(indexedIdentitySQL)
	searchManufacturerSQL := "l.search_manufacturer"
	searchBrandJoin := ""
	if query.Search != "" {
		searchManufacturerSQL = "concat_ws(' ',nullif(lower(search_hardware.data->>'manufacturer'),''),nullif(l.search_manufacturer,''))"
		searchBrandJoin = " LEFT JOIN passive_hardware_current search_hardware ON search_hardware.identity_key=" + identitySQL
	}
	profileOS := "''::text"
	if query.OSFamily != "" {
		profileOS = "coalesce(rec.os_family,'')"
	}
	filterCandidates := query.State != "identified" && (query.DeviceType != "" || query.includeCandidateTypes || query.View == "iot" || query.Capability == "dumb")
	pageProfiles := query.Search == "" && query.Category == "" && query.OSFamily == "" && !filterCandidates
	recognitionSource := `SELECT rec.endpoint_id,coalesce(rec.role,'') role,coalesce(rec.os_family,'') os_family,rec.last_seen profile_seen,
 ` + indexedProfileConfidenceSQL("rec") + ` profile_confidence,
 ` + indexedProfileConflictSQL("rec") + ` profile_conflict
 FROM endpoint_recognition_summary rec
 JOIN (SELECT DISTINCT recognition_endpoint COLLATE "C" recognition_endpoint FROM seed_rows) relevant ON relevant.recognition_endpoint=rec.endpoint_id`
	if pageProfiles {
		// Display-only clues can be joined after the page limit.
		recognitionSource = `SELECT ''::text endpoint_id,''::text role,''::text os_family,
 NULL::timestamptz profile_seen,0::double precision profile_confidence,false profile_conflict WHERE false`
	}
	// An ACK for a canonical MAC only adds its display endpoint. Identity,
	// profile lookup and scope admission already use the observed MAC.
	// Noncanonical observations keep their original lease lookup before grouping.
	usableSourceMAC := "(l.search_mac ~ '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$' AND l.search_mac<>'00:00:00:00:00:00')"
	sourceRows := ` SELECT l.ctid observation_tid,l.id,l.device_key,l.origin,l.observed_at,l.valid_until,
 coalesce(d.node,'') sensor_id,coalesce(d.site,'') site_id,
 coalesce(d.domain,'') access_domain,coalesce(d.vlan,'') vlan,coalesce(d.vrf,'') vrf,
 coalesce(d.mac,'') raw_mac,coalesce(d.ip,'') raw_ip,
 coalesce(d.evidence->'observer'->>'capture_scope_issue','')='' capture_scope_valid,
 coalesce(d.evidence->'subject'->>'campus_id','') source_campus,
 ` + searchIP + ` search_ip,lower(coalesce(d.mac,'')) search_mac,
 ` + searchName + ` search_name,` + searchType + ` search_device_type,
 ` + searchManufacturer + ` search_manufacturer,` + searchModel + ` search_model,
 ` + caps + ` observation_capabilities,
 ` + productType + ` product_type,` + productEvidence + ` product_evidence,
 ` + dhcpType + ` dhcp_candidate_type,
 (l.valid_until>now() AND d.confidence IN ('strong','confirmed') AND coalesce(d.evidence->'observer'->>'capture_scope_issue','')='') service_clue_valid
 FROM discovery_observation_latest l
 CROSS JOIN LATERAL jsonb_to_record(CASE WHEN jsonb_typeof(l.data)='object' THEN l.data END) AS d(
  node text,site text,domain text,vlan text,vrf text,mac text,ip text,confidence text,evidence jsonb,
  name text,device_type text,manufacturer text,model_name text,capabilities jsonb,event_id text,product_clue jsonb)
 WHERE ` + strings.Join(baseWhere, " AND ") + ``
	extraCTE, groupedUnion := "", ""
	if query.structured {
		if hours := cachedGroupWindow(query); hours > 0 {
			extraCTE = cachedGroupCTE(hours)
			groupedUnion = cachedGroupedSQL(query, pageProfiles)
			baseWhere = append(baseWhere, "NOT EXISTS(SELECT 1 FROM cache_groups cg WHERE cg.identity_key=l.base_identity)")
		}
		if query.groupPageRows {
			baseWhere = append(baseWhere, "l.base_identity IN (SELECT c.identity_key FROM candidates c JOIN cache_groups g USING(identity_key))")
		}
		sourceRows = structuredSourceSQL(query, baseWhere)
		identitySQL = "CASE WHEN coalesce(l.display_endpoint,'')='' THEN l.base_identity ELSE " + identitySQL + " END"
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
)` + extraCTE + `, source_rows AS MATERIALIZED (
 ` + sourceRows + `
), candidate_links AS NOT MATERIALIZED (
 SELECT l.*,coalesce(i.endpoint_id,ix.endpoint_id,dl.endpoint_id) linked_endpoint,
  CASE WHEN ` + usableSourceMAC + ` AND i.endpoint_id IS NULL AND ix.endpoint_id IS NULL
   THEN l.source_campus END lease_campus
 FROM source_rows l
 LEFT JOIN LATERAL (
  SELECT i.endpoint_id FROM discovery_identity_links i
  WHERE i.observation_id=l.id AND l.raw_mac='' LIMIT 1
 ) i ON true
 LEFT JOIN LATERAL (
  SELECT ix.endpoint_id FROM discovery_identity_links ix
  WHERE ix.observation_id=l.id AND l.raw_mac<>''
   AND (coalesce(ix.basis->>'mac','')='' OR lower(ix.endpoint_id)<>'mac:'||lower(ix.basis->>'mac'))
  LIMIT 1
 ) ix ON true
 LEFT JOIN LATERAL (
  SELECT dl.endpoint_id FROM device_address_leases dl
  WHERE dl.event_id=l.id AND dl.action='ack'
   AND dl.sensor_id=l.sensor_id AND host(dl.ip)=l.raw_ip
   AND dl.campus_id=l.source_campus AND dl.endpoint_id='mac:'||lower(l.raw_mac)
   AND i.endpoint_id IS NULL AND ix.endpoint_id IS NULL AND NOT ` + usableSourceMAC + `
  LIMIT 1
 ) dl ON true
), display_links AS NOT MATERIALIZED (
 SELECT l.*,CASE WHEN t.mac IS NOT NULL THEN 'mac:'||t.mac ELSE l.linked_endpoint END display_endpoint
 FROM candidate_links l LEFT JOIN trusted_address t ON t.observation_id=l.id
), seed_rows AS MATERIALIZED (
 SELECT l.observation_tid,l.id,l.device_key,l.origin,l.observed_at,l.valid_until,l.sensor_id,
 l.search_ip,l.search_mac,l.search_name,l.search_device_type,` + searchManufacturerSQL + ` search_manufacturer,l.search_model,
 ` + identitySQL + ` identity_key,l.vlan,l.raw_ip,l.observation_capabilities,l.product_type,l.product_evidence,l.dhcp_candidate_type,l.service_clue_valid,
 (l.capture_scope_valid AND l.sensor_id<>'' AND l.site_id<>'' AND l.access_domain<>''
  AND lower(l.raw_mac) ~ '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$' AND lower(l.raw_mac)<>'00:00:00:00:00:00'
  AND (coalesce(l.display_endpoint,'')='' OR lower(l.display_endpoint)='mac:'||lower(l.raw_mac))) profile_identity_verified,
 coalesce(l.display_endpoint,'') linked_endpoint,l.lease_campus,
 coalesce(l.display_endpoint,'mac:'||lower(l.raw_mac)) recognition_endpoint
 FROM display_links l` + searchBrandJoin + `
), recognition AS MATERIALIZED (
 ` + recognitionSource + `
), candidate_rows AS MATERIALIZED (
 SELECT l.observation_tid,l.id,l.device_key,l.origin,l.observed_at,l.valid_until,l.sensor_id,
 l.search_ip,l.search_mac,l.search_name,l.search_device_type,l.search_manufacturer,l.search_model,
 l.identity_key,l.vlan,l.observation_capabilities,l.raw_ip,l.product_type,l.product_evidence,l.service_clue_valid,l.linked_endpoint,l.lease_campus,l.recognition_endpoint,l.profile_identity_verified,
 ` + subnet + ` subnet,
 coalesce(rec.role,'') profile_role,coalesce(rec.profile_confidence,0) profile_confidence,
 ` + profileOS + ` profile_os,` + profileType + ` profile_type,
 coalesce(rec.profile_conflict,false) AND coalesce(rec.role,'')<>'' profile_conflict,
 CASE WHEN l.profile_identity_verified AND l.dhcp_candidate_type<>'' AND NOT coalesce(rec.profile_conflict,false)
  AND coalesce(rec.role,'') IN ('',l.dhcp_candidate_type) THEN l.dhcp_candidate_type
 ELSE ` + hardwareProfileCandidateSQL("rec.role", "coalesce(rec.profile_confidence,0)", "coalesce(rec.profile_conflict,false)", "rec.profile_seen") + ` END profile_candidate_role
 FROM seed_rows l LEFT JOIN recognition rec ON rec.endpoint_id=l.recognition_endpoint
), candidate_grouped AS (
 SELECT identity_key COLLATE "C" identity_key,max(vlan) vlan,coalesce(min(device_key COLLATE "C") FILTER (WHERE search_mac<>''),min(device_key COLLATE "C")) device_key,
 max(observed_at) last_seen,max(profile_os) profile_os,
 ` + subnets + ` subnets,
 coalesce(array_agg(DISTINCT product_type) FILTER (WHERE product_type<>''),'{}'::text[]) product_types,
 bool_or(raw_ip<>'') has_observed_ip,
 bool_or(search_mac<>'' OR linked_endpoint<>'' OR product_evidence) has_device_evidence,
 bool_or(service_clue_valid AND observation_capabilities ?| ARRAY['printing','scanning','casting','media_rendering','network_video','voice']) has_iot_service,
 bool_or(observation_capabilities ?| ARRAY['printing','scanning']) has_printing,
 bool_or(observation_capabilities ? 'network_video') has_video,
 bool_or(observation_capabilities ?| ARRAY['casting','media_rendering']) has_media,
 CASE WHEN count(DISTINCT profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'')=1
 THEN min(profile_candidate_role) FILTER (WHERE valid_until>now() AND profile_candidate_role<>'') ELSE '' END candidate_role
 FROM candidate_rows GROUP BY identity_key COLLATE "C"` + candidateHaving + groupedUnion + `
), candidate_types AS (
 ` + indexedTypesProjection(true) + `
), candidate_classified AS (
 SELECT *,` + indexedClassificationProjection(true) + ` classification_status FROM candidate_types
), candidate_source AS (
 SELECT *,` + indexedCategorySQL("") + ` category FROM candidate_classified
), matched AS (
 SELECT * FROM candidate_source` + matchedWhere + `
)`
	return indexedDeviceSelection{Query: query, CTE: statement, Args: args, PageProfiles: pageProfiles}
}

// Fetch documents only after the bounded identity page. The locator is used
// solely in this statement's MVCC snapshot. Common MAC links were already
// coalesced in seed_rows: the legacy page_link CASE fallback was unreachable,
// so probing the historical link table here would only add random disk reads.
func buildHardwareIndexedPage(selection indexedDeviceSelection, positionWhere, limitParameter string) (string, error) {
	profiles := "l.profile_role,l.profile_confidence,l.profile_conflict,l.profile_candidate_role"
	profileJoin := ""
	if selection.PageProfiles {
		confidence, conflict := indexedProfileConfidenceSQL("page_rec"), indexedProfileConflictSQL("page_rec")
		profiles = "coalesce(page_rec.role,'')," + confidence + ",(" + conflict + ") AND coalesce(page_rec.role,'')<>''," +
			hardwareProfileCandidateSQL("page_rec.role", confidence, "("+conflict+")", "page_rec.last_seen")
		profileJoin = "LEFT JOIN endpoint_recognition_summary page_rec ON page_rec.endpoint_id=l.recognition_endpoint\n"
	}
	pageSource := "JOIN discovery_observation_latest page_o ON page_o.ctid=l.observation_tid"
	if selection.Query.structured {
		pageSource = `JOIN discovery_list_observation f ON f.ctid=l.observation_tid
JOIN discovery_observation_latest page_o ON (page_o.device_key,page_o.source_id,page_o.origin,page_o.service_type,page_o.port)=(f.device_key,f.source_id,f.origin,f.service_type,f.port)`
	}
	statement := selection.CTE
	pageRows := "candidate_rows"
	cachedRows := ""
	if cachedGroupWindow(selection.Query) > 0 {
		// The cached groups are disjoint and already admitted for the default
		// device scope. Bound this ordered branch before combining with live rows.
		statement = strings.Replace(statement, "candidate_role FROM cache_groups g", "candidate_role FROM (SELECT * FROM cache_groups"+positionWhere+" ORDER BY last_seen DESC,identity_key LIMIT $"+limitParameter+") g", 1)
		q := selection.Query
		q.groupPageRows = true
		detail, err := buildIndexedDeviceSelection(q)
		if err != nil {
			return "", err
		}
		cachedRows = `, page_members AS (
 SELECT l.* FROM candidate_rows l JOIN candidates c USING(identity_key)
 UNION ALL SELECT * FROM (` + detail.CTE + ` SELECT * FROM candidate_rows) cached_page
)`
		pageRows = "page_members"
	}
	return statement + `, candidates AS (
 SELECT identity_key,device_key,last_seen,category FROM matched` + positionWhere + `
 ORDER BY last_seen DESC,identity_key COLLATE "C" LIMIT $` + limitParameter + `
)` + cachedRows + `
SELECT c.identity_key,c.device_key,page_o.data,coalesce(dl.endpoint_id,l.linked_endpoint) linked_endpoint,` + profiles + `,c.category
FROM ` + pageRows + ` l JOIN candidates c USING(identity_key)
` + pageSource + `
LEFT JOIN LATERAL (
 SELECT dl.endpoint_id FROM device_address_leases dl
 WHERE l.linked_endpoint='' AND dl.sensor_id=l.sensor_id AND dl.campus_id=l.lease_campus
  AND dl.event_id=l.id AND dl.action='ack' AND host(dl.ip)=l.raw_ip AND dl.endpoint_id='mac:'||l.search_mac
 LIMIT 1
) dl ON true
` + profileJoin + `ORDER BY c.last_seen DESC,c.identity_key COLLATE "C",l.id`, nil
}
