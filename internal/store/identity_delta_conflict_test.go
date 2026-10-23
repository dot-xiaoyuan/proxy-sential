package store

import (
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestIdentityDeltaCaptureConflictDoesNotAssignAccount(t *testing.T) {
	at := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	log := []snapshotMeta{{Scope: reconcileScope, SnapshotID: "full", ObservedAt: at, IntervalSeconds: 60, CaptureStartedAt: at.Add(-10 * time.Second)}}
	facts := []policy.Session{{ID: "s", AccountID: "a", IP: "192.0.2.1", Source: reconcileScope.Source, SensorID: reconcileScope.SensorID, CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain, ConfirmedAt: at.Add(-time.Second), StartedAt: at.Add(-time.Second)}}
	got := policySessionsFromProjection(facts, log, nil, at.Add(time.Second))
	if len(got) != 1 || got[0].IdentityIssue != "identity_snapshot_capture_conflict" || got[0].AccountID != "" {
		t.Fatalf("ambiguous result: %+v", got)
	}
	facts[0].ConfirmedAt = at.Add(-20 * time.Second)
	got = policySessionsFromProjection(facts, log, nil, at.Add(time.Second))
	if len(got) == 0 || got[0].IdentityIssue != "" {
		t.Fatalf("prior event is not capture conflict: %+v", got)
	}
}

func TestIdentityDeltaLaterEventResolvesOnlyFutureAttribution(t *testing.T) {
	at := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	log := []snapshotMeta{{ObservedAt: at, CaptureStartedAt: at.Add(-10 * time.Second)}}
	facts := []policy.Session{{ConfirmedAt: at.Add(-time.Second)}, {ConfirmedAt: at.Add(time.Second)}}
	if !identityCaptureConflict(facts, log, at, at.Add(2*time.Second)) {
		t.Fatal("later event cannot erase historical ambiguity")
	}
	if identityCaptureConflict(facts, log, at.Add(time.Second), at.Add(2*time.Second)) {
		t.Fatal("resolved future attribution must not stay blocked")
	}
}
