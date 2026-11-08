package store

import "testing"

func TestSSDPServerDeviceType(t *testing.T) {
	for _, tc := range []struct{ server, want string }{
		{"Linux/3.14.0 UPnP/1.0 Roku/3500X", "media_device"},
		{"Synology/DSM UPnP/1.0", "server"},
		{"RouterOS/7.10 UPnP/1.0", "router"},
		{"nginx/1.20 UPnP/1.0", ""},
	} {
		if got := ssdpServerDeviceType(tc.server); got != tc.want {
			t.Fatalf("server=%q got=%q want=%q", tc.server, got, tc.want)
		}
	}
}
