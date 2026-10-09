package store

import (
	"context"
	"proxy-sentinel/internal/sharedaccess"
	"testing"
	"time"
)

func TestSharedBehaviorCanonicalTimeRepairsOldWindowEndPostgres(t *testing.T) {
	s := routerProjectionPrivatePostgres(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := sharedaccess.BehaviorAssessment{ObservationID: "source-time", SensorID: "office", IP: "192.0.2.22", Status: "confirmed", RuleVersion: sharedaccess.BehaviorRuleVersion, Confidence: 90, CoverageState: "verified", FirstSeen: now.Add(-10 * time.Minute), LastSeen: now, WindowStart: now.Add(-10 * time.Minute), WindowEnd: now, ExpiresAt: now.Add(20 * time.Minute), SignalGroups: []string{"ieee1905_association"}}
	if err := s.persistSharedBehavior(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	item.LastSeen = now.Add(-3 * time.Minute)
	if err := s.persistSharedBehavior(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	var canonical time.Time
	if err := s.pg.db.QueryRow(`SELECT last_seen FROM shared_behavior_observations WHERE observation_id='source-time'`).Scan(&canonical); err != nil || !canonical.Equal(item.LastSeen) {
		t.Fatalf("old synthetic window end retained as source time: %s want=%s err=%v", canonical, item.LastSeen, err)
	}
	// Correct source timestamps continue to advance monotonically afterward.
	item.LastSeen = now.Add(-2 * time.Minute)
	if err := s.persistSharedBehavior(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	item.LastSeen = now.Add(-4 * time.Minute)
	if err := s.persistSharedBehavior(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if err := s.pg.db.QueryRow(`SELECT last_seen FROM shared_behavior_observations WHERE observation_id='source-time'`).Scan(&canonical); err != nil || !canonical.Equal(now.Add(-2*time.Minute)) {
		t.Fatalf("source replay regressed a valid timestamp: %s %v", canonical, err)
	}
}
