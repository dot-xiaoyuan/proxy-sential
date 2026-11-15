package discovery

import (
	"testing"
	"time"
)

func TestHardwareAuditDoesNotTurnProductIntoOwnership(t *testing.T) {
	at := time.Now().UTC()
	o := hardwareTestObservation(at)
	a, err := AuditHardwareObservation(o, at)
	if err != nil || !a.OwnershipAccepted || a.Result.Type != "access_control" {
		t.Fatalf("valid self-report lost: %+v %v", a, err)
	}
	o.MAC = ""
	a, err = AuditHardwareObservation(o, at)
	if err != nil || a.OwnershipAccepted || a.Result.Type != "" || a.FieldReplay.Type != "access_control" || a.Stage != "device_attribution" || len(a.RuleInputs) != 1 {
		t.Fatalf("missing ownership hidden: %+v %v", a, err)
	}
	o = hardwareTestObservation(at)
	o.Withdrawn = true
	a, err = AuditHardwareObservation(o, at)
	if err != nil || a.Result.Type != "" || a.Stage != "evidence_validity" {
		t.Fatalf("withdrawn proof became type: %+v %v", a, err)
	}
}
func TestSIPClientProductReachesHardwareInput(t *testing.T) {
	at := time.Now().UTC()
	o := hardwareTestObservation(at)
	o.Origin = "sip"
	o.Evidence.Flow = map[string]any{"src_ip": o.IP, "dst_ip": "10.0.0.8", "direction": "client"}
	o.Evidence.Payload = map[string]any{"hardware_identity": "unique_binding", "user_agent": "Huawei eSpace 7910 V200R003C00"}
	f, err := HardwareFactFromObservation(o)
	if err != nil || f == nil || len(f.Signals) != 1 || f.Signals[0].Field != "sip_user_agent" || f.Evidence()[0].Direction != "client" {
		t.Fatalf("SIP product lost: %+v %v", f, err)
	}
	o.IP = "10.0.0.8"
	f, err = HardwareFactFromObservation(o)
	if err != nil || f == nil || len(f.Signals) != 0 {
		t.Fatalf("client UA moved to SIP server: %+v %v", f, err)
	}
}
