package fingerprint

import (
	"testing"
	"time"
)

func TestAirPlayCompatibilityCannotProveAppleHardware(t *testing.T) {
	now := time.Now().UTC()
	model := hardwareSignal("dns_sd", "dns_sd_model", "AppleTV3,1", "old-model")
	model.ObservedAt = now.Add(-time.Minute)
	marker := hardwareSignal("dns_sd", "dns_sd_receiver_implementation", "com.tcl.MultiScreenInteraction_TV", "tcl-airplay")
	marker.ObservedAt = now.Add(-time.Second)
	r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{model, marker}}, now)
	if r.Model != "" || r.Manufacturer == "Apple" || r.Type != "" {
		t.Fatalf("compatibility identifier confirmed Apple hardware: %+v", r)
	}
	if r.RejectedReasons["protocol_compatibility_model"] == 0 {
		t.Fatal("missing explanation for suppressed compatibility model")
	}
	model.ObservedAt = now
	marker.ObservedAt = now.Add(-6 * time.Minute)
	r = EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{model, marker}}, now)
	if r.Model == "" || r.Manufacturer != "Apple" {
		t.Fatalf("older compatibility evidence permanently blocked newer model: %+v", r)
	}
	marker.ValidUntil = now.Add(time.Minute)
	if r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{model, marker}}, now); r.Model != "" {
		t.Fatal("active receiver TTL ignored")
	}
	marker.ValidUntil = now.Add(-time.Second)
	if r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{model, marker}}, now); r.Model == "" {
		t.Fatal("expired receiver TTL blocked newer model")
	}
	marker.Association = "untrusted"
	marker.ObservedAt = now
	if r = EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{model, marker}}, now); r.Model == "" {
		t.Fatal("untrusted marker erased direct product")
	}
}
