package discovery

import "strings"

// A product annotation can select an IP-level clue, never a confirmed physical
// identity. Require its stored endpoint, event and full scope to match the row.
const indexedProductAttributionSQL = `l.valid_until>now()
 AND d.product_clue->>'attribution' IN ('response_ip','request_ip')
 AND d.product_clue->>'event_id'=d.event_id
 AND d.product_clue->>'ip'=d.ip
 AND d.product_clue->>'sensor_id'=d.node
 AND d.product_clue->>'site'=d.site
 AND d.product_clue->>'domain'=d.domain
 AND coalesce(d.product_clue->>'vlan','')=coalesce(d.vlan,'')
 AND coalesce(d.product_clue->>'vrf','')=coalesce(d.vrf,'')`

const indexedValidProductTypeSQL = `CASE WHEN ` + indexedProductAttributionSQL + `
 AND d.product_clue->>'product_status'='identified'
 THEN coalesce(d.product_clue->>'type','') ELSE '' END`

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
