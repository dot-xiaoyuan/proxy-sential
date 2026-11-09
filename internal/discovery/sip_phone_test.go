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

func TestSIPServerIdentityClassifiesVoiceGateways(t *testing.T) {
	for _, tc := range []struct {
		server, kind, brand, model string
	}{
		{"eSpace U1960/V200R003C20SPC300B015", "voice_gateway", "Huawei", "eSpace U1960"},
		{"Huawei eSpace U1981/V200R003C00", "voice_gateway", "Huawei", "eSpace U1981"},
		{"Asterisk PBX 1.8.26.0", "voice_gateway", "Asterisk", ""},
		{"FreeSWITCH 1.10.7", "voice_gateway", "FreeSWITCH", ""},
		{"Cisco-SIPGateway/IOS-15.6.3.x", "voice_gateway", "Cisco", "SIPGateway"},
		{"Grandstream UCM6202 1.0.20.16", "voice_gateway", "Grandstream", "UCM6202"},
		{"Cisco-CP-8841/9.4.1.1", "", "", ""},
	} {
		kind, brand, model := SIPServerIdentity(tc.server)
		if kind != tc.kind || brand != tc.brand || model != tc.model {
			t.Fatalf("%q => %q %q %q", tc.server, kind, brand, model)
		}
	}
}

