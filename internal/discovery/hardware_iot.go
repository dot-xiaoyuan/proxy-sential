package discovery

import "strings"

// A product annotation can select an IP-level clue, never a confirmed physical
// identity. Require its stored endpoint, event and full scope to match the row.
const indexedProductAttributionSQL = `l.valid_until>now()
 AND l.data->'product_clue'->>'attribution' IN ('response_ip','request_ip')
 AND l.data->'product_clue'->>'event_id'=l.data->>'event_id'
 AND l.data->'product_clue'->>'ip'=l.data->>'ip'
 AND l.data->'product_clue'->>'sensor_id'=l.data->>'node'
 AND l.data->'product_clue'->>'site'=l.data->>'site'
 AND l.data->'product_clue'->>'domain'=l.data->>'domain'
 AND coalesce(l.data->'product_clue'->>'vlan','')=coalesce(l.data->>'vlan','')
 AND coalesce(l.data->'product_clue'->>'vrf','')=coalesce(l.data->>'vrf','')`

const indexedValidProductTypeSQL = `CASE WHEN ` + indexedProductAttributionSQL + `
 AND l.data->'product_clue'->>'product_status'='identified'
 THEN coalesce(l.data->'product_clue'->>'type','') ELSE '' END`

func hardwareIoTAdmissionSQL() string {
	types := make([]string, 0, len(IoTTypes)+4)
	for _, kind := range IoTTypes {
		types = append(types, "'"+kind.ID+"'")
	}
	types = append(types, "'environment_monitor'", "'ups'", "'pdu'", "'media_device'")
	set := "ARRAY[" + strings.Join(types, ",") + "]"
	// An explicit non-IoT hardware type takes precedence over weak service
	// capabilities. Profile and IP product clues remain candidate identities.
	return "(projection_type=ANY(" + set + ") OR (classification_status='candidate' AND coalesce(projection_type,'')='' AND (candidate_role=ANY(" + set + ") OR product_types && " + set + " OR (candidate_role='' AND cardinality(product_types)=0 AND has_iot_service))))"
}
