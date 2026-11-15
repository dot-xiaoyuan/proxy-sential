package fingerprint

import (
	"testing"
	"time"
)

func TestSIPPhoneModelRequiresOwnClientProtocolField(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct{ protocol, field, value, direction, kind string }{
		{"sip", "sip_user_agent", "Huawei eSpace 7910 V200R003C00", "client", "voip_phone"},
		{"sip", "sip_user_agent", "Huawei eSpace 7910 V200R003C00", "server", ""},
		{"http", "sip_user_agent", "Huawei eSpace 7910 V200R003C00", "client", ""},
		{"sip", "sip_user_agent", "Mozilla Huawei eSpace 7910 V200R003C00", "client", ""},
		{"sip", "sip_user_agent", "Huawei", "client", ""},
	} {
		s := hardwareSignal(tc.protocol, tc.field, tc.value, "sip-product-test")
		s.Direction = tc.direction
		r := EvaluateHardware(HardwareInput{IdentityTrusted: true, Evidence: []EvidenceSignal{s}}, now)
		if r.Type != tc.kind {
			t.Fatalf("%+v: %+v", tc, r)
		}
		if tc.kind != "" && (r.Model != "eSpace 7910" || r.Manufacturer != "Huawei") {
			t.Fatalf("product incomplete: %+v", r)
		}
		if r := EvaluateHardware(HardwareInput{Evidence: []EvidenceSignal{s}}, now); r.Type != "" {
			t.Fatal("unowned UA confirmed hardware")
		}
	}
}
