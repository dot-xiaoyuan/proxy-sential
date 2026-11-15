package discovery

import (
	"testing"
	"time"
)

func TestIPProductDoesNotInventPhysicalIdentity(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now.Add(-time.Minute))
	o.Origin, o.MAC = "snmp", ""
	o.Evidence.Payload = map[string]any{"is_response": true, "response_source_ip": o.IP, "system_object_id": "1.3.6.1.4.1.52674.500", "snmp_varbinds": map[string]string{"1.3.6.1.4.1.318.1.4.2.2.1.2.1": "NetBotz 750"}}
	clue, err := BuildIPProductClue(o, now)
	if err != nil || clue == nil || clue.Type != "environment_monitor" || clue.Model != "NetBotz 750" || clue.Attribution != "response_ip" || len(clue.Sources) == 0 {
		t.Fatalf("IP product evidence lost: %+v %v", clue, err)
	}
	if fact, err := HardwareFactFromObservation(o); err != nil || fact != nil {
		t.Fatal("IP product was promoted into a physical identity", fact, err)
	}
	for _, change := range []func(*Observation){
		func(v *Observation) { v.Evidence.Payload["is_response"] = false },
		func(v *Observation) { v.Evidence.Payload["response_source_ip"] = "203.0.113.1" },
		func(v *Observation) { v.Withdrawn = true },
		func(v *Observation) { v.ObservedAt = now.Add(time.Hour) },
		func(v *Observation) { v.Domain = "" },
	} {
		copy := o
		copy.Evidence.Payload = map[string]any{}
		for k, v := range o.Evidence.Payload {
			copy.Evidence.Payload[k] = v
		}
		change(&copy)
		if clue, _ := BuildIPProductClue(copy, now); clue != nil {
			t.Fatal("unverified response became product evidence", clue)
		}
	}
}
