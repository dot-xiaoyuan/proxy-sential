package fingerprint

import "testing"

// These self-reported DHCP hostnames occur in the campus sample. A model name
// is useful only when it is in the device's own hostname, not a client UA.
func TestCampusDHCPHostnameFamilies(t *testing.T) {
	cases := []struct {
		hostname, brand, deviceType string
	}{
		{"Xiaomi-15-Pro", "Xiaomi", "mobile"},
		{"Xiaomi-Pad-7", "Xiaomi", "tablet"},
		{"REDMI-K80-Pro", "Redmi", "mobile"},
		{"OPPO-Find-X9", "OPPO", "mobile"},
		{"OPPO-Reno14", "OPPO", "mobile"},
		{"OPPO-Pad-3", "OPPO", "tablet"},
		{"vivo-X200s", "vivo", "mobile"},
		{"vivo-S30", "vivo", "mobile"},
		{"vivo-Pad-Air", "vivo", "tablet"},
		{"iQOO-Neo11", "iQOO", "mobile"},
		{"realme-GT-Neo5", "realme", "mobile"},
	}
	for _, tc := range cases {
		t.Run(tc.hostname, func(t *testing.T) {
			got := Default().IdentifySignals(Signals{MAC: "02:00:00:00:00:01", Hostnames: []string{tc.hostname}})
			if got.Brand != tc.brand || got.DeviceType != tc.deviceType || got.Model == "" {
				t.Fatalf("hostname %q: got %+v", tc.hostname, got)
			}
		})
	}
}

func TestCampusDHCPHostnameFamiliesDoNotPromoteClientOrRouter(t *testing.T) {
	for _, value := range []string{"Xiaomi-Router-AX3000", "Redmi-Router-AX6", "OPPO-Phone", "vivo-router", "iQOO", "realme", "Xiaomi-Pad", "vivo-Pad"} {
		got := Default().IdentifySignals(Signals{MAC: "02:00:00:00:00:01", Hostnames: []string{value}})
		if got.DeviceType == "mobile" || got.DeviceType == "tablet" {
			t.Fatalf("ambiguous hostname %q was promoted: %+v", value, got)
		}
	}
	got := Default().IdentifySignals(Signals{UserAgents: []string{"Xiaomi-15-Pro"}})
	if got.Brand != "" || got.Model != "" || got.DeviceType != "" {
		t.Fatalf("client UA established a physical device: %+v", got)
	}
}
