package controlplane

import (
	"encoding/json"
	"proxy-sentinel/internal/discovery"
	"strings"
	"testing"
)

func TestDiscoveryPermissionsAndSecrets(t *testing.T) {
	for _, p := range []string{"/discovery/sources", "/discovery/scan-profiles/a/trial", "/discovery/tasks/a/stop", "/discovery/preview"} {
		if requiredPermission("POST", p) != "integrations:write" {
			t.Fatal("mutation permission", p)
		}
		if requiredPermission("GET", p) != "identity:read" {
			t.Fatal("read permission", p)
		}
	}
	b, e := json.Marshal(discovery.Task{EncryptedSecret: "do-not-expose"})
	if e != nil || strings.Contains(string(b), "do-not-expose") {
		t.Fatal("task credential disclosure")
	}
}
