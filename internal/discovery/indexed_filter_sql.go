package discovery

// These expressions read the maintained latest-observation and recognition
// indexes. Raw observation history is never rebuilt for a list request.
const indexedObservationTypeSQL = `CASE
 WHEN origin IN ('lldp','cdp') AND lower(concat_ws(' ',data->>'name',data->'evidence'->'payload'->>'system_name',data->'evidence'->'payload'->>'system_description')) LIKE '%ikuai%' THEN 'router'
 WHEN origin='dhcp' AND coalesce(data->>'device_type','')='' AND (lower(concat_ws(' ',data->>'name',data->'evidence'->'payload'->>'hostname',data->'evidence'->'payload'->>'device_hint',data->'evidence'->'payload'->>'vendor_class')) LIKE '%android%' OR lower(concat_ws(' ',data->>'name',data->'evidence'->'payload'->>'hostname',data->'evidence'->'payload'->>'device_hint',data->'evidence'->'payload'->>'vendor_class')) LIKE '%vivo-%') THEN 'mobile'
 ELSE coalesce(data->>'device_type','') END`

func indexedProfileConfidenceSQL(alias string) string {
	return "coalesce(NULLIF(" + alias + ".summary->>'device_type_confidence','')::double precision," + alias + ".confidence,0)"
}
func indexedProfileConflictSQL(alias string) string {
	return "CASE WHEN jsonb_array_length(coalesce(" + alias + ".summary->'conflict_dimensions','[]'::jsonb))>0 THEN " + alias + ".summary->'conflict_dimensions' ? 'device_type' ELSE coalesce(" + alias + ".conflict,false) END"
}

// mobile is the broad DHCP family; a specific tablet/phone conclusion refines
// it. Distinct specific types still conflict. Keep this aligned with
// refineDeviceTypes in the bounded Go page aggregation.
const indexedEffectiveTypesSQL = `ARRAY(SELECT DISTINCT kind FROM unnest(types) kind
 WHERE kind<>'' AND (kind<>'mobile' OR NOT types && ARRAY['tablet','phone','smartphone']) ORDER BY kind)`

const indexedClassificationStateSQL = `CASE
 WHEN NOT is_current THEN 'expired'
 WHEN type_conflict OR cardinality(effective_types)>1 THEN 'conflict'
 WHEN cardinality(effective_types)=1 THEN 'identified'
 ELSE 'candidate' END`

// Only trustworthy identities cross discovery keys. Names and IP addresses are
// searchable evidence, never identity aliases in this paginated read model.
const indexedIdentitySQL = `CASE
 WHEN lower(coalesce(i.endpoint_id,dl.endpoint_id,'')) ~ '^mac:[0-9a-f][02468ace](:[0-9a-f]{2}){5}$'
 AND lower(coalesce(i.endpoint_id,dl.endpoint_id,''))<>'mac:00:00:00:00:00:00'
 AND (coalesce(l.data->>'mac','')='' OR lower(coalesce(i.endpoint_id,dl.endpoint_id,''))='mac:'||lower(l.data->>'mac')) THEN
 jsonb_build_array('identity',coalesce(l.data->>'node',''),coalesce(l.data->>'site',''),coalesce(l.data->>'domain',''),coalesce(l.data->>'vlan',''),coalesce(l.data->>'vrf',''),'mac',substring(lower(coalesce(i.endpoint_id,dl.endpoint_id,'')) FROM 5))::text
 WHEN coalesce(i.endpoint_id,dl.endpoint_id,'')<>'' THEN
 jsonb_build_array('identity',coalesce(l.data->>'node',''),coalesce(l.data->>'site',''),coalesce(l.data->>'domain',''),coalesce(l.data->>'vlan',''),coalesce(l.data->>'vrf',''),'endpoint',lower(coalesce(i.endpoint_id,dl.endpoint_id,'')))::text
 WHEN coalesce(l.data->>'mac','')<>'' THEN
 jsonb_build_array('identity',coalesce(l.data->>'node',''),coalesce(l.data->>'site',''),coalesce(l.data->>'domain',''),coalesce(l.data->>'vlan',''),coalesce(l.data->>'vrf',''),'mac',lower(l.data->>'mac'))::text
 ELSE jsonb_build_array('discovery_key',l.device_key)::text END`

const indexedObservationCapabilitiesSQL = `CASE WHEN origin IN ('lldp','cdp') AND lower(concat_ws(' ',data->>'name',data->'evidence'->'payload'->>'system_name',data->'evidence'->'payload'->>'system_description')) LIKE '%ikuai%'
 THEN coalesce(data->'capabilities','[]'::jsonb)||'["routing"]'::jsonb
 ELSE coalesce(data->'capabilities','[]'::jsonb) END`

func indexedCategorySQL(view string) string {
	if view == "iot" {
		return "CASE WHEN has_printing THEN 'printer' WHEN has_video THEN 'camera' WHEN has_media THEN 'media' ELSE '' END"
	}
	expression := "CASE WHEN classification_status='identified' THEN CASE effective_types[1]"
	for _, kind := range DeviceTypes {
		expression += " WHEN '" + kind.ID + "' THEN '" + deviceCategory(kind.ID) + "'"
	}
	return expression + " ELSE 'identity_only' END ELSE 'identity_only' END"
}
