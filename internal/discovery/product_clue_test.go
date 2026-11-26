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

func TestSIPIPProductRequiresClientOwnershipAndUniqueSource(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now.Add(-time.Minute))
	o.Origin, o.MAC = "sip", ""
	o.EventID = "zeek-aaaaaaaaaaaaaaaaaaaaaaaa"
	o.Evidence.EventID, o.Evidence.Source = o.EventID, "zeek"
	o.Evidence.Payload = map[string]any{"method": "REGISTER", "user_agent": "Huawei eSpace 7910 V200R003C00"}
	o.Evidence.Flow = map[string]any{"src_ip": o.IP, "dst_ip": "10.0.0.8", "direction": "client"}
	o.Evidence.RawRef = map[string]any{"content_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	c, err := BuildIPProductClue(o, now)
	if err != nil || c == nil || c.Type != "voip_phone" || c.Attribution != "request_ip" {
		t.Fatalf("valid phone self-report lost: %+v %v", c, err)
	}
	if f, _ := HardwareFactFromObservation(o); f != nil {
		t.Fatal("phone IP self-report became hardware identity")
	}
	o.Evidence.Flow["src_ip"] = "10.0.0.9"
	if c, _ := BuildIPProductClue(o, now); c != nil {
		t.Fatal("remote UA attributed to phone IP")
	}
	o.Evidence.Flow["src_ip"] = o.IP
	o.EventID = "zeek-e3b0c44298fc1c149afbf4c8"
	if c, _ := BuildIPProductClue(o, now); c != nil {
		t.Fatal("legacy nonunique SIP reference accepted")
	}
}

func TestCAPWAPAndDahuaIPProductClues(t *testing.T) {
	now := time.Now().UTC()
	sha := "1b74a264007a827aa9fa28d7ce4a8a9a2bedf9c0c23ba61e7c92730871120341"

	capwap := hardwareTestObservation(now.Add(-time.Minute))
	capwap.Origin, capwap.MAC, capwap.DeviceType, capwap.Manufacturer = "capwap", "", "access_point", "Huawei"
	capwap.Evidence.Payload = map[string]any{
		"is_request":     true,
		"message_type":   "echo_request",
		"manufacturer":   "Huawei",
		"payload_sha256": sha,
	}
	capwap.Evidence.Flow = map[string]any{"src_ip": capwap.IP, "dst_ip": "10.126.1.10"}
	clue, err := BuildIPProductClue(capwap, now)
	if err != nil || clue == nil || clue.Type != "access_point" || clue.ProductStatus != "identified" || clue.Attribution != "request_ip" || clue.Manufacturer != "Huawei" {
		t.Fatalf("unexpected CAPWAP IP product clue: %+v err=%v", clue, err)
	}
	if fact, err := HardwareFactFromObservation(capwap); err != nil || fact != nil {
		t.Fatalf("cross-L3 CAPWAP must not invent physical MAC identity: %+v err=%v", fact, err)
	}
	capwap.Evidence.Payload["is_request"] = false
	if clue, _ := BuildIPProductClue(capwap, now); clue != nil {
		t.Fatalf("AC response must not become AP product clue: %+v", clue)
	}

	dahua := hardwareTestObservation(now.Add(-time.Minute))
	dahua.Origin, dahua.MAC, dahua.DeviceType, dahua.Manufacturer, dahua.ModelName = "dahua_discovery", "", "camera", "Dahua", "DH-IPC-HFW5241E"
	dahua.Evidence.Payload = map[string]any{
		"is_response":    true,
		"manufacturer":   "Dahua",
		"product_model":  "DH-IPC-HFW5241E",
		"payload_sha256": sha,
	}
	dahua.Evidence.Flow = map[string]any{"src_ip": dahua.IP, "dst_ip": "239.255.255.251"}
	dClue, err := BuildIPProductClue(dahua, now)
	if err != nil || dClue == nil || dClue.Type != "camera" || dClue.ProductStatus != "identified" || dClue.Attribution != "response_ip" || dClue.Model != "DH-IPC-HFW5241E" {
		t.Fatalf("unexpected Dahua IP product clue: %+v err=%v", dClue, err)
	}
}
