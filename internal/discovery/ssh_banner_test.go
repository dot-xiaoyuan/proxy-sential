package discovery

import "testing"

func TestSSHBannerIdentity(t *testing.T) {
	for _, tc := range []struct {
		banner, wantType, wantBrand, wantOS string
	}{
		{"SSH-2.0-Comware-7.1.070", "switch", "H3C", "Comware"},
		{"SSH-2.0-Ruijie_1.0", "switch", "Ruijie", "RGOS"},
		{"SSH-2.0-HUAWEI-1.5", "switch", "Huawei", "VRP"},
		{"SSH-2.0-Cisco-1.25", "router", "Cisco", "IOS"},
		{"SSH-2.0-ROSSSH", "router", "MikroTik", "RouterOS"},
		{"SSH-2.0-dropbear_2022.83", "", "", "Embedded Linux"},
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "", "", "Linux"},
		{"SSH-2.0-OpenSSH_for_Windows_8.6", "", "", "Windows"},
		{"SSH-2.0-OpenSSH_9.6", "", "", ""},
		{"not-ssh", "", "", ""},
	} {
		gotType, gotBrand, gotOS := SSHBannerIdentity(tc.banner)
		if gotType != tc.wantType || gotBrand != tc.wantBrand || gotOS != tc.wantOS {
			t.Errorf("SSHBannerIdentity(%q)=(%q,%q,%q) want (%q,%q,%q)", tc.banner, gotType, gotBrand, gotOS, tc.wantType, tc.wantBrand, tc.wantOS)
		}
	}
}
