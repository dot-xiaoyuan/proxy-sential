package violation

import (
	"testing"
	"time"
)

func TestContinuousOnlineToleratesVirtualDownButNotMissingData(t *testing.T) {
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	seven := now.Add(-7 * 24 * time.Hour)
	intervals := []Interval{{Start: seven.Add(-time.Hour), End: now.Add(-3 * 24 * time.Hour)}, {Start: now.Add(-3*24*time.Hour + 5*time.Minute), End: now}}
	if !ContinuousOnline(intervals, now, 7*24*time.Hour, 10*time.Minute) {
		t.Fatal("five-minute virtual down should be tolerated")
	}
	intervals[1].Start = now.Add(-3*24*time.Hour + 20*time.Minute)
	if ContinuousOnline(intervals, now, 7*24*time.Hour, 10*time.Minute) {
		t.Fatal("unknown 20-minute gap must not count")
	}
}

func TestSimulatedNoticesAndNightDecision(t *testing.T) {
	now := time.Date(2026, 10, 22, 2, 0, 0, 0, time.FixedZone("CST", 8*3600))
	c := Case{AccountID: "student", AssessmentID: "router-1", Status: "open"}
	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(i) * 48 * time.Hour)
		if !c.AdvanceNotice(at, true) {
			t.Fatalf("notice %d absent", i+1)
		}
	}
	if c.AdvanceNotice(now.Add(6*24*time.Hour), true) {
		t.Fatal("fourth notice")
	}
	if got := c.Decide(now.Add(6*24*time.Hour), true, false, false); got.Kind != "拟封禁" || got.DurationDays != 1 {
		t.Fatalf("unexpected decision: %+v", got)
	}
	if got := c.Decide(now.Add(6*24*time.Hour+10*time.Hour), true, false, false); got.Kind != "阻止" {
		t.Fatalf("daytime decision: %+v", got)
	}
	if got := c.Decide(now.Add(6*24*time.Hour), false, false, false); got.Kind != "阻止" {
		t.Fatalf("stale evidence: %+v", got)
	}
}

func TestRouterEligibilityRejectsHotspotAndMissingAccount(t *testing.T) {
	if RouterEligible("hotspot", true, false, []string{"a"}, true) {
		t.Fatal("hotspot eligible")
	}
	if RouterEligible("router", true, false, nil, true) {
		t.Fatal("missing account eligible")
	}
	if !RouterEligible("router", true, false, []string{"a"}, true) {
		t.Fatal("confirmed router excluded")
	}
}
