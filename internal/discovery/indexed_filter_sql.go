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
