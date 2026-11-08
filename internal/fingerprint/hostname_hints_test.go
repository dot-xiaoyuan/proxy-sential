package fingerprint

import (
	"testing"
	"time"
)

func TestHostnameDeviceHintsIdentifyDeviceClass(t *testing.T) {
	for _, tc := range []struct {
		hostname string
		want     string
	}{
		{"LAPTOP-0EVL266V", "desktop"},
		{"DESKTOP-ABC123", "desktop"},
		{"lenovo-pc", "desktop"},
		{"iQOO-Pad5-Pro", "tablet"},
		{"iqoo-z9", "mobile"},
	} {
		res := Default().IdentifyEvidence("02:00:00:00:00:01", []EvidenceSignal{
			{Protocol: "dhcp", Field: "hostname", Value: tc.hostname, Direction: "device", Association: "direct", SourceFamily: "dhcp"},
		}, time.Now().UTC())
		if res.DeviceType != tc.want || res.DeviceTypeConfidence <= 0 {
			t.Fatalf("%s: type=%q conf=%.2f, want %q", tc.hostname, res.DeviceType, res.DeviceTypeConfidence, tc.want)
		}
	}
}

func TestHostnameDeviceHintsDoNotOverrideStrongerType(t *testing.T) {
	res := Default().IdentifyEvidence("02:00:00:00:00:02", []EvidenceSignal{
		{Protocol: "dhcp", Field: "hostname", Value: "laptop-01", Direction: "device", Association: "direct", SourceFamily: "dhcp"},
		{Protocol: "mdns", Field: "mdns_model", Value: "Brother HL-L2350DW", Direction: "device", Association: "direct", SourceFamily: "mdns"},
	}, time.Now().UTC())
	if res.DeviceType == "desktop" {
		t.Fatalf("hostname hint overrode a stronger printer model: %+v", res)
	}
}
