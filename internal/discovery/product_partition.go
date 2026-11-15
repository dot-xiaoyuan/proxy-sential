package discovery

import (
	"encoding/json"
	"sort"
)

// SNMPProductPartition separates retained response field sets, not values.
// A later sysObjectID packet must not erase the earlier sysDescr response.
// This is an internal projection key, not an advertised service or identity.
func SNMPProductPartition(o Observation) string {
	p := o.Evidence.Payload
	if o.Origin != "snmp" || p["is_response"] != true || str(p, "response_source_ip") != o.IP {
		return ""
	}
	signals, err := hardwareObservationSignals(o)
	if err != nil {
		return ""
	}
	fields := make([]string, 0, len(signals)+32)
	for _, s := range signals {
		if s.Field != "snmp_oid_values" {
			fields = append(fields, s.Field)
			continue
		}
		var values map[string]string
		if json.Unmarshal([]byte(s.Value), &values) != nil {
			return ""
		}
		for oid := range values {
			fields = append(fields, "oid:"+oid)
		}
	}
	if len(fields) == 0 {
		return ""
	}
	sort.Strings(fields)
	return "snmp-fields:" + hardwareHash(fields)
}
