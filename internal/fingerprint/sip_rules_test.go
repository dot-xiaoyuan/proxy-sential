package fingerprint

import (
	"strings"
	"testing"
)

func TestSIPUserAgentRulesClassifyVoIPPhones(t *testing.T) {
	for _, tc := range []struct{ ua, brand, model string }{
		{"Huawei eSpace 7910 V200R003C00", "Huawei", "eSpace 7910"},
		{"Yealink SIP-T46S 66.86.0.15", "Yealink", "SIP-T46S"},
		{"Grandstream GXP1625 1.0.4.61", "Grandstream", "GXP1625"},
	} {
		res := Default().IdentifySignals(Signals{ProtocolFields: map[string][]string{"sip_user_agent": {tc.ua}}})
		if res.DeviceType != "voip_phone" || res.Brand != tc.brand || !strings.Contains(res.Model, tc.model) {
			t.Fatalf("%q => type=%q brand=%q model=%q", tc.ua, res.DeviceType, res.Brand, res.Model)
		}
	}
}
