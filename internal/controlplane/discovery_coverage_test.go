package controlplane

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaptureScopeExpiryNotice(t *testing.T) {
	base := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "scope.json")
	write := func(until time.Time) {
		t.Helper()
		body := `{"schema_version":"capture-scope/v1","sensor_id":"sensor-a","collector_instance_id":"collector-a","campus_id":"campus-a","access_domain":"domain-a","valid_from":"2026-10-01T00:00:00Z","valid_until":"` + until.Format(time.RFC3339) + `"}`
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(base.Add(15 * 24 * time.Hour))
	if got := captureScopeExpiry(path, base); got.Status != "valid" {
		t.Fatalf("early reminder: %+v", got)
	}
	write(base.Add(14 * 24 * time.Hour))
	if got := captureScopeExpiry(path, base); got.Status != "expiring" || got.ValidUntil == "" {
		t.Fatalf("missing reminder: %+v", got)
	}
	write(base)
	if got := captureScopeExpiry(path, base); got.Status != "expired" {
		t.Fatalf("expired scope accepted: %+v", got)
	}
}
