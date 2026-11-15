package discovery

import (
	"testing"
	"time"
)

func TestSNMPProductPartitionsRetainSeparateFieldSets(t *testing.T) {
	o := hardwareTestObservation(time.Now().UTC())
	o.Origin = "snmp"
	o.MAC = ""
	o.Evidence.Payload = map[string]any{"is_response": true, "response_source_ip": o.IP, "system_description": "switch model", "snmp_varbinds": map[string]string{"1.3.6.1.2.1.1.1.0": "switch model"}}
	descr := SNMPProductPartition(o)
	if descr == "" {
		t.Fatal("description has no partition")
	}
	o.Evidence.Payload["system_description"] = "new model"
	if SNMPProductPartition(o) != descr {
		t.Fatal("product value must not multiply latest rows")
	}
	o.Evidence.Payload = map[string]any{"is_response": true, "response_source_ip": o.IP, "system_object_id": "1.3.6.1.4.1.4881", "snmp_varbinds": map[string]string{"1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.4881"}}
	if got := SNMPProductPartition(o); got == "" || got == descr {
		t.Fatal("OID overwrites description", got)
	}
	o.Evidence.Payload["is_response"] = false
	if SNMPProductPartition(o) != "" {
		t.Fatal("legacy response gained trusted partition")
	}
}
