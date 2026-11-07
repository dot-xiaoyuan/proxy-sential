package fingerprint

import (
	"testing"
	"time"
)

func TestUserAgentHintsIdentifyDeviceClass(t *testing.T) {
	for _, tc := range []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", "mobile"},
		{"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15", "tablet"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15", "desktop"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "desktop"},
		{"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36", "mobile"},
	} {
		res := Default().IdentifyEvidence("02:00:00:00:00:03", []EvidenceSignal{
			{Protocol: "http", Field: "user_agent", Value: tc.ua, Direction: "client", Association: "direct", SourceFamily: "http"},
		}, time.Now().UTC())
		if res.DeviceType != tc.want {
			t.Fatalf("%s: type=%q want %q", tc.ua, res.DeviceType, tc.want)
		}
	}
}

func TestUserAgentHintDoesNotOverrideStrongerType(t *testing.T) {
	res := Default().IdentifyEvidence("02:00:00:00:00:04", []EvidenceSignal{
		{Protocol: "http", Field: "user_agent", Value: "Mozilla/5.0 (Windows NT 10.0)", Direction: "client", Association: "direct", SourceFamily: "http"},
		{Protocol: "mdns", Field: "mdns_model", Value: "Brother HL-L2350DW", Direction: "device", Association: "direct", SourceFamily: "mdns"},
	}, time.Now().UTC())
	if res.DeviceType == "desktop" {
		t.Fatalf("UA hint overrode a stronger printer model: %+v", res)
	}
}
