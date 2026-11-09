package discovery

import "testing"

func TestSIPPhoneIdentity(t *testing.T) {
	for _, tc := range []struct{ ua, kind, brand, model string }{
		{"Huawei eSpace 7910 V200R003C00", "voip_phone", "Huawei", "eSpace 7910"},
		{"Yealink SIP-T46S 66.86.0.15", "voip_phone", "Yealink", "SIP-T46S"},
		{"Cisco-CP-8841/9.4.1.1", "voip_phone", "Cisco", "CP-8841"},
		{"Grandstream GXP1625 1.0.4.61", "voip_phone", "Grandstream", "GXP1625"},
		{"PolycomSoundPointIP-SPIP_550-UA/3.2.2.1138", "voip_phone", "Polycom", "SPIP_550"},
		{"Asterisk PBX 1.8.26.0", "", "", ""},
		{"Cisco-SIPGateway/IOS-15.6.3.x", "", "", ""},
		{"SIP/2.0", "", "", ""},
	} {
		kind, brand, model := SIPPhoneIdentity(tc.ua)
		if kind != tc.kind || brand != tc.brand || model != tc.model {
			t.Fatalf("%q => %q %q %q", tc.ua, kind, brand, model)
		}
	}
}
