package census

import "strings"

// Every census endpoint, including the comparison stream, selects this same
// current relation. Activity expiry never changes a known hardware type.
func terminalProjectionSQL(v2 bool) string {
	if !v2 {
		return "passive_census_terminal_current"
	}
	return `(SELECT identity_key,scope_key,device_key,sensor_id,campus_id,access_domain,vlan,vrf,mac,
 coalesce(NULLIF(hardware_type,''),(SELECT min(kind) FROM jsonb_array_elements_text(coalesce(data->'hardware_conflicting_types','[]'::jsonb)) kind WHERE kind IN ('printer','camera','recorder','access_control','voip_phone','environment_monitor','ups','pdu')),'') effective_type,
 CASE WHEN hardware_type_status='revoked' THEN 'expired' ELSE hardware_type_status END classification_status,
 first_seen,last_seen,active_until effective_until FROM passive_hardware_current)`
}
func terminalStatusSQL(v2 bool) string {
	if v2 {
		return "classification_status"
	}
	return "CASE WHEN classification_status<>'expired' AND effective_until<=now() THEN 'expired' ELSE classification_status END"
}

func censusPriorityTypes(v2 bool) []string {
	if !v2 {
		return priorityTypes
	}
	return append(append([]string{}, priorityTypes...), "environment_monitor", "ups", "pdu")
}
func censusPriorityArraySQL(v2 bool) string {
	return "ARRAY['" + strings.Join(censusPriorityTypes(v2), "','") + "']"
}
