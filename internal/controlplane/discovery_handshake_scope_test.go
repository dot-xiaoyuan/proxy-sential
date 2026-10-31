package controlplane

import (
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/store"
)

func TestMappedDiscoveryHandshakeScopeRequiresExplicitMatchingCIDR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.json")
	data := `{"schema_version":"discovery-handshake-scope-map/v1","links":[{"sensor_id":"sensor-a","discovery_campus_id":"ncu","discovery_access_domain":"bond0-passive-pilot","handshake_campus_id":"ncu","handshake_access_domain":"bond0-router-minimal-overnight","user_cidrs":["10.202.0.0/16"]}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	scope := store.SharedObservationScope{SensorID: "sensor-a", CampusID: "ncu", AccessDomain: "bond0-passive-pilot", IP: "10.202.90.3"}
	got, ok, err := mappedDiscoveryHandshakeScope(path, scope)
	if err != nil || !ok || got.AccessDomain != "bond0-router-minimal-overnight" || got.IP != scope.IP {
		t.Fatalf("mapped=%+v ok=%v err=%v", got, ok, err)
	}
	scope.IP = "10.203.90.3"
	if _, ok, err := mappedDiscoveryHandshakeScope(path, scope); err != nil || ok {
		t.Fatalf("out-of-range IP matched: ok=%v err=%v", ok, err)
	}
	scope.IP = "10.202.90.3"
	scope.AccessDomain = "unrelated"
	if _, ok, err := mappedDiscoveryHandshakeScope(path, scope); err != nil || ok {
		t.Fatalf("unrelated discovery domain matched: ok=%v err=%v", ok, err)
	}
	if _, ok, err := mappedDiscoveryHandshakeScope("", scope); err != nil || ok {
		t.Fatalf("missing explicit map matched: ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"discovery-handshake-scope-map/v1","links":[{"sensor_id":"sensor-a","discovery_campus_id":"ncu","discovery_access_domain":"bond0-passive-pilot","handshake_campus_id":"ncu","handshake_access_domain":"first","user_cidrs":["10.202.0.0/16"]},{"sensor_id":"sensor-a","discovery_campus_id":"ncu","discovery_access_domain":"bond0-passive-pilot","handshake_campus_id":"ncu","handshake_access_domain":"second","user_cidrs":["10.202.0.0/16"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	scope.AccessDomain = "bond0-passive-pilot"
	if _, _, err := mappedDiscoveryHandshakeScope(path, scope); err == nil {
		t.Fatal("ambiguous scope mapping accepted")
	}
}
