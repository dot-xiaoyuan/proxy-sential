package fingerprint

import "testing"

func TestTTLOSHintFillsEmptyOSFingerprint(t *testing.T) {
	res := Default().IdentifySignals(Signals{OSHint: "Windows"})
	if res.OSFamily != "Windows" || res.OSFamilyConfidence > .6 {
		t.Fatalf("ttl hint not applied at clue level: %+v", res)
	}
	if res.Brand != "" || res.Model != "" || res.DeviceType != "" {
		t.Fatalf("ttl hint established hardware: %+v", res)
	}
}
