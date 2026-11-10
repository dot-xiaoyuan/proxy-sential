package sharedaccess

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

func TestLoadDoesNotAdmitPartialCaptureAsSharedViolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.json")
	raw := `{"schema_version":"shared-access-sources/v1","version":"site-v1","freshness_seconds":600,"skip_capture_verification":true,"min_device_bound":1,"sources":[{"sensor_id":"sensor-a","source":"packet-sidecar","campus_id":"campus-a","access_domain":"domain-a"}],"identity_mappings":[{"sensor_id":"sensor-a","campus_id":"campus-a","access_domain":"domain-a","identity_source":"ncu","identity_sensor_id":"identity-a","identity_campus_id":"campus-a","identity_access_domain":"domain-a","valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
	// The old worker promoted a partial window to complete when the bypass
	// setting was loaded, even though it had no strong topology anchor.
	w := Window{ID: "partial", RuleVersion: RuleVersion, IP: "192.0.2.8", SensorID: "sensor-a", CampusID: "campus-a", AccessDomain: "domain-a", Sources: []string{"packet-sidecar"}, From: now.Add(-time.Minute), To: now, LastObservedAt: now, EventIDs: []string{"event-a"}, Complete: true, CoverageVerified: true, DeviceLowerBound: 1}
	sessions := []policy.Session{{ID: "session-a", AccountID: "account-a", IP: w.IP, Source: "ncu", SensorID: "identity-a", CampusID: "campus-a", AccessDomain: "domain-a", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-2 * time.Minute), now}, HeartbeatSeconds: 60}}
	result := EvaluateObservation(w, cfg, sessions, now)
	decision := NewObservationDecision(w, result, cfg, now)
	if cfg.SkipCaptureVerification || cfg.DeviceBound() < 2 || decision.Result == "matched" || decision.Violated {
		t.Fatalf("partial capture produced a violation: config=%+v result=%+v decision=%+v", cfg, result, decision)
	}
}
