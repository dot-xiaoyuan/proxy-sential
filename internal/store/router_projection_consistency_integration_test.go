package store

import (
	"context"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/sharedaccess"
)

func routerProjectionPrivatePostgres(t *testing.T) *DBStore {
	t.Helper()
	s := activityV3PrivatePostgres(t)
	for _, name := range []string{"059_router_observations.sql", "066_shared_behavior_observations.sql", "067_shared_behavior_rule_history.sql", "075_shared_behavior_current_discovery.sql"} {
		raw, err := os.ReadFile("../../migrations/postgres/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.pg.db.Exec(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func routerProjectionFact(now time.Time) evidence.RouterEvidence {
	return evidence.RouterEvidence{EvidenceID: "router-time-fact", AssessmentID: "router-time-assessment", EndpointID: "mac:00:11:22:33:44:55", IP: "192.0.2.22", MAC: "00:11:22:33:44:55", Kind: "router_signal", Role: "router", Source: "test", SourceFamily: "dhcp", Strength: "strong", Score: 70, RuleID: "explicit-router-model", RuleVersion: fingerprint.DefaultRouterRuleSet().Version, AssociationQuality: "mac", Brand: "TestVendor", Model: "TestRouter", FirstSeen: now.Add(-2 * time.Hour).Format(time.RFC3339Nano), LastSeen: now.Add(-2 * time.Hour).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
}

func TestRouterRefreshPreservesFirstSeenPostgres(t *testing.T) {
	s := routerProjectionPrivatePostgres(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fact := routerProjectionFact(now)
	write := func() {
		t.Helper()
		if err := s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{fact}}); err != nil {
			t.Fatal(err)
		}
	}
	write()
	first := fact.FirstSeen
	fact.FirstSeen = now.Add(-time.Hour).Format(time.RFC3339Nano)
	fact.LastSeen = fact.FirstSeen
	write()
	detail, found, err := s.GetRouterObservation(ctx, fact.AssessmentID)
	if err != nil || !found {
		t.Fatalf("detail found=%v err=%v", found, err)
	}
	if detail.FirstSeen != first || len(detail.Evidence) != 1 || detail.Evidence[0].FirstSeen != first {
		t.Fatalf("new batch reset original discovery: verdict=%s fact=%+v want=%s", detail.FirstSeen, detail.Evidence, first)
	}
}

func TestRouterReadModelsUseCanonicalTimesPostgres(t *testing.T) {
	s := routerProjectionPrivatePostgres(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fact := routerProjectionFact(now)
	if err := s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	first, last, expires := now.Add(-72*time.Hour), now.Add(-time.Minute), now.Add(30*time.Minute)
	if _, err := s.pg.db.Exec(`UPDATE router_assessments SET first_seen=$2,last_seen=$3,expires_at=$4 WHERE assessment_id=$1`, fact.AssessmentID, first, last, expires); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pg.db.Exec(`UPDATE router_evidence_facts SET first_seen=$2,last_seen=$3,expires_at=$4 WHERE evidence_id=$1`, fact.EvidenceID, first, last, expires); err != nil {
		t.Fatal(err)
	}
	assertTimes := func(label string, item evidence.RouterAssessment) {
		t.Helper()
		if item.FirstSeen != first.Format(time.RFC3339Nano) || item.LastSeen != last.Format(time.RFC3339Nano) || item.ExpiresAt != expires.Format(time.RFC3339Nano) {
			t.Errorf("%s returned stale JSON times: %+v", label, item)
		}
	}
	detail, found, err := s.GetRouterObservation(ctx, fact.AssessmentID)
	if err != nil || !found {
		t.Fatalf("detail found=%v err=%v", found, err)
	}
	assertTimes("detail", detail.RouterAssessment)
	if len(detail.Evidence) != 1 || detail.Evidence[0].FirstSeen != first.Format(time.RFC3339Nano) || detail.Evidence[0].ExpiresAt != expires.Format(time.RFC3339Nano) {
		t.Errorf("fact returned stale source times: %+v", detail.Evidence)
	}
	page, err := s.ListRouterObservations(ctx, RouterQuery{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list=%+v err=%v", page, err)
	}
	assertTimes("list", page.Items[0])
	summaries, err := s.RouterObservationSummaries(ctx, []string{fact.EndpointID})
	if err != nil {
		t.Fatal(err)
	}
	assertTimes("endpoint summary", summaries[fact.EndpointID])
}

func TestRouterConflictOnlyChangeCreatesAuditableHistoryPostgres(t *testing.T) {
	s := routerProjectionPrivatePostgres(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fact := routerProjectionFact(now)
	if err := s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	before, _, err := s.GetRouterObservation(ctx, fact.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	conflict := fact
	conflict.EvidenceID = "alias-conflict"
	conflict.Kind = "conflict"
	conflict.Score = 0
	conflict.Conflict = true
	conflict.ConflictCode = "ambiguous_association"
	started := time.Now().UTC()
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{conflict}}); err != nil {
		t.Fatal(err)
	}
	after, _, err := s.GetRouterObservation(ctx, fact.AssessmentID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Confidence != before.Confidence || after.Status != before.Status || len(after.Conflicts) != 1 {
		t.Fatalf("fixture did not isolate a conflict-only change: before=%+v after=%+v", before.RouterAssessment, after.RouterAssessment)
	}
	if len(after.History) != len(before.History)+1 || len(after.History[len(after.History)-1].Conflicts) != 1 {
		t.Fatalf("conflict omitted from audit at unchanged score: %+v", after.History)
	}
	changed, err := time.Parse(time.RFC3339Nano, after.History[len(after.History)-1].ChangedAt)
	if err != nil || changed.Before(started.Add(-time.Millisecond)) {
		t.Fatalf("audit backdated to old packet time: %s err=%v", changed, err)
	}
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{conflict}}); err != nil {
		t.Fatal(err)
	}
	repeated, _, err := s.GetRouterObservation(ctx, fact.AssessmentID)
	if err != nil || len(repeated.History) != len(after.History) {
		t.Fatalf("unchanged conflict duplicated history: %+v err=%v", repeated.History, err)
	}
}

func TestSharedBehaviorDetailRespectsDatabaseRetirementPostgres(t *testing.T) {
	s := routerProjectionPrivatePostgres(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := sharedaccess.BehaviorAssessment{ObservationID: "retired-shared", SensorID: "test", IP: "192.0.2.82", RuleVersion: sharedaccess.BehaviorRuleVersion, Status: "confirmed", Confidence: 90, CoverageState: "verified", StrongAnchor: "coexisting_device_models", DeviceLowerBound: 2, FirstSeen: now.Add(-10 * time.Minute), LastSeen: now, WindowStart: now.Add(-10 * time.Minute), WindowEnd: now, ExpiresAt: now.Add(24 * time.Hour), SignalGroups: []string{"device_model", "tcp_stack", "tls_stack"}}
	if err := s.persistSharedBehavior(ctx, item); err != nil {
		t.Fatal(err)
	}
	if err := s.publishSharedBehaviorCurrent(ctx, "test", []string{item.ObservationID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pg.db.Exec(`UPDATE shared_behavior_observations SET expires_at=$2 WHERE observation_id=$1`, item.ObservationID, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	detail, found, err := s.GetSharedBehavior(ctx, item.ObservationID)
	if err != nil || !found {
		t.Fatalf("detail found=%v err=%v", found, err)
	}
	if detail.Current || !detail.ExpiresAt.Equal(now.Add(-time.Second)) {
		t.Fatalf("database retirement ignored by detail: current=%v expires=%s", detail.Current, detail.ExpiresAt)
	}
	page, err := s.ListSharedBehavior(ctx, SharedBehaviorQuery{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("retired row leaked to list: %+v %v", page, err)
	}
	if len(detail.History) != 1 {
		t.Fatalf("retirement lost immutable history: %+v", detail.History)
	}
}

func TestRouterHistoryDedupHandlesLegacyFutureTimestampPostgres(t *testing.T) {
	s := routerProjectionPrivatePostgres(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fact := routerProjectionFact(now)
	if err := s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	// Legacy workers recorded packet time as verdict time, including timestamps
	// from clocks ahead of the host. Keep that record without letting it remain
	// the newest verdict forever and generate identical audit entries each loop.
	if _, err := s.pg.db.Exec(`UPDATE router_assessment_history SET changed_at=$2 WHERE assessment_id=$1`, fact.AssessmentID, now.Add(8*time.Hour)); err != nil {
		t.Fatal(err)
	}
	conflict := fact
	conflict.EvidenceID = "clock-conflict"
	conflict.Kind = "conflict"
	conflict.Conflict = true
	conflict.ConflictCode = "ambiguous_association"
	conflict.Score = 0
	for i := 0; i < 3; i++ {
		if err := s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{conflict}}); err != nil {
			t.Fatal(err)
		}
	}
	detail, found, err := s.GetRouterObservation(ctx, fact.AssessmentID)
	if err != nil || !found {
		t.Fatalf("detail found=%v err=%v", found, err)
	}
	if len(detail.History) != 2 || len(detail.History[0].Conflicts) != 0 || len(detail.History[1].Conflicts) != 1 {
		t.Fatalf("legacy future record distorted verdict sequence: %+v", detail.History)
	}
}
