package discovery

import "testing"

func TestPassiveDHCPClientCandidateRequiresOneCoherentMessage(t *testing.T) {
	for _, test := range []struct{ vendor, host, options, want string }{
		{"HP LaserJet", "NPI1AB3CD", "1,3,6,15", "printer"},
		{"Brother printer", "BRW1234AABBCCDD", "1, 3, 6, 15", "printer"},
		{"Yealink SIP-T46U", "SIP-T46U", "1,3,6,15", "voip_phone"},
		{"MSFT 5.0", "NPI1AB3CD", "1,3,6,15", ""},
		{"HP LaserJet", "USER-PC", "1,3,6,15", ""},
		{"HP LaserJet", "NPI1AB3CD", "1,1,6", ""},
		{"HP LaserJet", "NPI1AB3CD", "1,3,6,999", ""},
		{"", "", "1,3,6,138,52,43,15,42,67,150", "access_point"},
		{"", "", "1,3,6,15,42,43,52,67,138,150", "access_point"},
		{"MSFT 5.0", "DESKTOP-1", "1,3,6,138,43,67,150", ""},
		{"android-dhcp-16", "", "1,3,6,138,43,67,150", ""},
		{"", "", "1,3,6,138", ""},
	} {
		if got := PassiveDHCPClientCandidate(test.vendor, test.host, test.options); got != test.want {
			t.Errorf("%v: got %q", test, got)
		}
	}
}
