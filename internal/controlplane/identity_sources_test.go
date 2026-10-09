package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

func TestIdentitySourceRegistrationAndNeverSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	raw := `{"schema_version":"identity-sources/v1","sources":[{"source":"srun","sensor_id":"vm190","campus_id":"test","access_domain":"portal","reconcile_interval_seconds":60}]}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	registered, err := loadIdentitySources(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{identitySources: registered}
	scope := store.IdentityScope{Source: "srun", SensorID: "vm190", CampusID: "test", AccessDomain: "portal"}
	if err = s.validateIdentitySourceContext(context.Background(), scope, 60); err != nil {
		t.Fatal(err)
	}
	if err = s.validateIdentitySourceContext(context.Background(), scope, 3600); err == nil {
		t.Fatal("sender changed freshness contract")
	}
	scope.CampusID = "other"
	if err = s.validateIdentitySourceContext(context.Background(), scope, 60); err == nil {
		t.Fatal("unregistered scope accepted")
	}
	statuses := s.mergeIdentitySources(nil, time.Now())
	if len(statuses) != 1 || statuses[0].State != "never_seen" {
		t.Fatal(statuses)
	}
	if err = os.WriteFile(path, []byte(`{"schema_version":"wrong","sources":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadIdentitySources(path); err == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestPolicyIdentityRequiresRegisteredSource(t *testing.T) {
	now := time.Now().UTC()
	session := policy.Session{ID: "session", AccountID: "account", Source: "auth", SensorID: "sensor", CampusID: "campus", AccessDomain: "access", IP: "192.0.2.1", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 3600}
	reader := policySandboxReader{sessions: []policy.Session{session}}
	s := &Server{}
	got, err := s.policySessions(context.Background(), reader, now)
	if err != nil || len(got) != 1 || got[0].State(now) != "unknown" || got[0].IdentityIssue != "unregistered_source" {
		t.Fatal(got, err)
	}
	s.identitySources = []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: "auth", SensorID: "sensor", CampusID: "campus", AccessDomain: "access"}, IntervalSeconds: 60}}
	got, err = s.policySessions(context.Background(), reader, now)
	if err != nil || got[0].State(now) != "active" || got[0].HeartbeatSeconds != 60 {
		t.Fatal(got, err)
	}
	if reader.sessions[0].HeartbeatSeconds != 3600 {
		t.Fatal("stored identity was mutated")
	}
	reader.sessions[0].ConfirmedAt = now.Add(-4 * time.Minute)
	got, err = s.policySessions(context.Background(), reader, now)
	if err != nil || got[0].State(now) != "unknown" {
		t.Fatal("sender-defined freshness accepted", got, err)
	}
	reader.sessions[0].CampusID = "other"
	got, err = s.policySessions(context.Background(), reader, now)
	if err != nil || got[0].IdentityIssue != "unregistered_source" {
		t.Fatal("scope mismatch accepted", got, err)
	}
}
