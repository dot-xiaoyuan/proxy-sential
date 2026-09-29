package store

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestIdentitySnapshotReplay(t *testing.T) {
	at := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	scope := IdentityScope{Source: "radius", SensorID: "sensor-a", CampusID: "east", AccessDomain: "wifi"}
	session := policy.Session{ID: "s1", AccountID: "alice", Source: scope.Source, SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: "192.0.2.1", StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}, HeartbeatSeconds: 600}
	other := session
	other.ID = "s2"
	other.SensorID = "sensor-b"
	snapshots := []IdentitySnapshot{{IdentityScope: scope, SnapshotID: "empty", ObservedAt: at.Add(time.Minute), IntervalSeconds: 60, Sessions: []policy.Session{}}}
	for _, tc := range []struct {
		at    time.Time
		state string
	}{{at.Add(30 * time.Second), "active"}, {at.Add(90 * time.Second), "ended"}} {
		got := reconcileIdentitySessions([]policy.Session{session, other}, snapshots, tc.at)
		for _, s := range got {
			if s.SensorID == "sensor-a" && s.State(tc.at) != tc.state {
				t.Fatalf("at %v: %+v", tc.at, s)
			}
			if s.SensorID == "sensor-b" && s.State(tc.at) != "active" {
				t.Fatal("snapshot crossed sensor scope")
			}
		}
	}
	// A late pre-snapshot fact must still be closed by the retained empty inventory.
	session.ConfirmedAt = at.Add(10 * time.Second)
	session.Confirmations = []time.Time{session.ConfirmedAt}
	got := reconcileIdentitySessions([]policy.Session{session}, snapshots, at.Add(90*time.Second))
	if len(got) != 1 || got[0].State(at.Add(90*time.Second)) != "ended" {
		t.Fatalf("late fact bypassed snapshot: %+v", got)
	}
}

func TestIdentitySnapshotFreshnessAndRecovery(t *testing.T) {
	at := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	scope := IdentityScope{Source: "radius", SensorID: "a", CampusID: "east", AccessDomain: "wifi"}
	online := policy.Session{ID: "s", AccountID: "alice", Source: scope.Source, SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: "192.0.2.1", StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}, HeartbeatSeconds: 60, Status: "reconcile"}
	snapshots := []IdentitySnapshot{{IdentityScope: scope, SnapshotID: "one", ObservedAt: at, IntervalSeconds: 60, Sessions: []policy.Session{online}}}
	// A fresh incremental heartbeat cannot conceal interrupted full reconciliation.
	heartbeat := online
	heartbeat.Status = "heartbeat"
	heartbeat.ConfirmedAt = at.Add(3 * time.Minute)
	heartbeat.Confirmations = []time.Time{heartbeat.ConfirmedAt}
	got := reconcileIdentitySessions([]policy.Session{heartbeat}, snapshots, heartbeat.ConfirmedAt)
	if len(got) != 1 || got[0].State(heartbeat.ConfirmedAt) != "unknown" {
		t.Fatalf("stale source trusted: %+v", got)
	}
	online.StartedAt = at.Add(4 * time.Minute)
	online.ConfirmedAt = online.StartedAt
	online.Confirmations = []time.Time{online.ConfirmedAt}
	snapshots = append(snapshots, IdentitySnapshot{IdentityScope: scope, SnapshotID: "two", ObservedAt: online.ConfirmedAt, IntervalSeconds: 60, Sessions: []policy.Session{online}})
	got = reconcileIdentitySessions([]policy.Session{heartbeat}, snapshots, online.ConfirmedAt)
	if len(got) != 1 || got[0].State(online.ConfirmedAt) != "active" {
		t.Fatalf("fresh snapshot failed recovery: %+v", got)
	}
}

func TestIdentitySourceOutageDoesNotRewriteHistoricalAttribution(t *testing.T) {
	at := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	scope := IdentityScope{Source: "radius", SensorID: "a", CampusID: "east", AccessDomain: "wifi"}
	online := policy.Session{ID: "s", AccountID: "alice", Source: scope.Source, SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, IP: "192.0.2.1", StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}, HeartbeatSeconds: 60, Status: "reconcile"}
	snapshots := []IdentitySnapshot{{IdentityScope: scope, ObservedAt: at, IntervalSeconds: 60, Sessions: []policy.Session{online}}}
	recovered := online
	recovered.ConfirmedAt = at.Add(10 * time.Minute)
	recovered.StartedAt = recovered.ConfirmedAt
	recovered.Confirmations = []time.Time{recovered.ConfirmedAt}
	snapshots = append(snapshots, IdentitySnapshot{IdentityScope: scope, ObservedAt: recovered.ConfirmedAt, IntervalSeconds: 60, Sessions: []policy.Session{recovered}})
	rows := reconcileIdentitySessions(nil, snapshots, at.Add(14*time.Minute))
	for _, tc := range []struct {
		minute int
		state  string
	}{{1, "resolved"}, {5, "unknown"}, {11, "resolved"}, {14, "unknown"}} {
		got := policy.Attribute(rows, scope.CampusID, scope.AccessDomain, online.IP, at.Add(time.Duration(tc.minute)*time.Minute))
		if got.State != tc.state {
			t.Fatalf("historical minute %d: %+v", tc.minute, got)
		}
	}
}
