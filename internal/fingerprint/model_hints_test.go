package fingerprint

import "testing"

func TestModelFamilyHintFillsEmptyDeviceClass(t *testing.T) {
	res := Default().IdentifySignals(Signals{ProtocolFields: map[string][]string{"mdns_model": {"AppleTV3,1"}}})
	if res.DeviceType != "media_device" || res.DeviceTypeConfidence > .8 {
		t.Fatalf("model family hint not applied: %+v", res)
	}
	if res.Brand != "" || res.Model != "" || res.OSFamily != "" {
		t.Fatalf("model family hint established hardware: %+v", res)
	}
	tablet := Default().IdentifySignals(Signals{ProtocolFields: map[string][]string{"mdns_model": {"iPad13,4"}}})
	if tablet.DeviceType != "tablet" {
		t.Fatalf("ipad model not typed: %+v", tablet)
	}
}
