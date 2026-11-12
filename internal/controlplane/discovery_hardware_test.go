package controlplane

import "testing"

func TestHardwareShadowDoesNotSwitchReadPath(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "")
	t.Setenv("PROXY_SENTINEL_HARDWARE_SHADOW", "true")
	if discoveryHardwareReadEnabled() {
		t.Fatal("shadow generation changed the read contract")
	}
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	if !discoveryHardwareReadEnabled() {
		t.Fatal("explicit v2 gate was ignored")
	}
}

func TestHardwareReadPathRejectsMixedProjectionConfiguration(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_V2", "false")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ", "false")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_CURRENT_SOURCE", "")
	if discoveryHardwareReadPathConflict() {
		t.Fatal("indexed read unexpectedly rejected")
	}
	for _, key := range []string{"PROXY_SENTINEL_DISCOVERY_V2", "PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ"} {
		t.Setenv(key, "true")
		if !discoveryHardwareReadPathConflict() {
			t.Fatalf("mixed read path accepted: %s", key)
		}
		t.Setenv(key, "false")
	}
}
