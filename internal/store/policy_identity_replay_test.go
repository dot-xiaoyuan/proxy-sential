package store

import (
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

func TestPolicySessionReplayRestartAndLateStop(t *testing.T) {
	base := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	row := func(second int, status string) policy.Session {
		at := base.Add(time.Duration(second) * time.Second)
		return policy.Session{ID: "reused", AccountID: "alice", Source: "radius", CampusID: "east", AccessDomain: "wifi", IP: "192.0.2.1", EndpointID: "device-1", StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}, HeartbeatSeconds: 60, Status: status}
	}
	start, stop, restart := row(0, "start"), row(30, "stop"), row(60, "start")
	stop.EndedAt = stop.ConfirmedAt
	// Arrival order differs from event time; duplicates must not change the result.
	sessions := foldPolicySessions([]policy.Session{restart, stop, start, stop, restart})
	if len(sessions) != 2 {
		t.Fatalf("want two separate login intervals: %+v", sessions)
	}
	for _, tc := range []struct {
		second int
		want   string
	}{{10, "resolved"}, {40, "unknown"}, {70, "resolved"}} {
		got := policy.Attribute(sessions, "east", "wifi", "192.0.2.1", base.Add(time.Duration(tc.second)*time.Second))
		if got.State != tc.want {
			t.Errorf("at %d: %+v", tc.second, got)
		}
	}
}

func TestPolicySessionReplaySparseHeartbeat(t *testing.T) {
	at := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	start := policy.Session{ID: "s", AccountID: "alice", Source: "radius", CampusID: "east", AccessDomain: "wifi", IP: "192.0.2.1", EndpointID: "device-1", MAC: "00:11:22:33:44:55", DeviceClass: "mobile", GroupID: "students", ProductID: "basic", HeartbeatSeconds: 60, StartedAt: at, ConfirmedAt: at, Confirmations: []time.Time{at}}
	heartbeat := start
	heartbeat.StartedAt = at.Add(time.Minute)
	heartbeat.ConfirmedAt = heartbeat.StartedAt
	heartbeat.Confirmations = []time.Time{heartbeat.ConfirmedAt}
	heartbeat.EndpointID = ""
	heartbeat.MAC = ""
	heartbeat.DeviceClass = ""
	heartbeat.GroupID = ""
	heartbeat.ProductID = ""
	heartbeat.HeartbeatSeconds = 0
	got := foldPolicySessions([]policy.Session{heartbeat, start})
	if len(got) != 1 || got[0].State(at.Add(2*time.Minute)) != "active" || got[0].DeviceClass != "mobile" || got[0].GroupID != "students" || got[0].ProductID != "basic" || got[0].MAC != start.MAC {
		t.Fatalf("sparse heartbeat discarded identity: %+v", got)
	}
}

func TestPolicySessionReplayDoesNotReopenOnHeartbeat(t *testing.T) {
	at := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	ended := policy.Session{ID: "s", AccountID: "alice", Source: "radius", StartedAt: at, ConfirmedAt: at, EndedAt: at, HeartbeatSeconds: 60}
	heartbeat := ended
	heartbeat.ConfirmedAt = at.Add(time.Minute)
	heartbeat.StartedAt = heartbeat.ConfirmedAt
	heartbeat.EndedAt = time.Time{}
	got := foldPolicySessions([]policy.Session{heartbeat, ended})
	if len(got) != 1 || got[0].State(at.Add(2*time.Minute)) != "ended" {
		t.Fatalf("heartbeat reopened closed interval: %+v", got)
	}
}

func TestPolicySessionExpiryBoundary(t *testing.T) {
	at := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	for _, confirmations := range [][]time.Time{nil, {at}} {
		s := policy.Session{AccountID: "alice", Source: "radius", StartedAt: at, ConfirmedAt: at, HeartbeatSeconds: 60, Confirmations: confirmations}
		if s.State(at.Add(180*time.Second-time.Nanosecond)) != "active" || s.State(at.Add(180*time.Second)) != "unknown" {
			t.Fatalf("three-heartbeat boundary inconsistent: %+v", s)
		}
	}
}

func TestPolicySessionSimultaneousConflictIsOrderIndependent(t *testing.T) {
	at := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	a := policy.Session{ID: "s", AccountID: "alice", Source: "radius", CampusID: "east", AccessDomain: "wifi", IP: "192.0.2.1", StartedAt: at, ConfirmedAt: at, HeartbeatSeconds: 60, Confirmations: []time.Time{at}}
	b := a
	b.AccountID = "bob"
	for _, rows := range [][]policy.Session{{a, b}, {b, a}} {
		got := foldPolicySessions(rows)
		if len(got) != 1 || !got[0].BindingConflict || policy.Attribute(got, "east", "wifi", a.IP, at).State == "resolved" {
			t.Fatalf("ambiguous identity resolved: %+v", got)
		}
	}
}
