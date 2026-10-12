package controlplane

import "testing"

func TestDeviceHistoryPermissions(t *testing.T) {
	for _, kind := range []string{"profile", "shared", "router", "discovery", "endpoint", "access"} {
		want := "identity:read"
		if kind == "profile" || kind == "shared" {
			want = "cases:read"
		}
		if got := requiredPermission("GET", "/device-history/"+kind+"/id"); got != want {
			t.Fatalf("%s: %s", kind, got)
		}
	}
	if got := requiredPermission("GET", "/shared-access/network-context"); got != "cases:read" {
		t.Fatal(got)
	}
}
