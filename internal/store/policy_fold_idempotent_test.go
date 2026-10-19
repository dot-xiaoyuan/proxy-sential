package store

import (
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

// A session that ended, came back and ended again is two sessions. Folding the already folded list
// again used to merge the second one back into the first once it carried a stop status, so the
// account looked logged out for the whole second session.
func TestFoldKeepsReopenedSessionAfterItEnds(t *testing.T) {
	base := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	login := eventRow("s", "a", "10.0.0.1", base)
	firstEnd := login
	firstEnd.Status, firstEnd.EndedAt, firstEnd.ConfirmedAt, firstEnd.StartedAt, firstEnd.Confirmations = "stop", base.Add(time.Hour), base.Add(time.Hour), base.Add(time.Hour), nil
	again := snapshotRowAt("s", "a", "10.0.0.1", base.Add(6*time.Hour))
	secondEnd := again
	secondEnd.Status, secondEnd.EndedAt, secondEnd.ConfirmedAt, secondEnd.Confirmations = "stop", base.Add(10*time.Hour), base.Add(10*time.Hour), nil
	once := foldPolicySessions([]policy.Session{login, firstEnd, again, secondEnd})
	twice := foldPolicySessions(once)
	for name, sessions := range map[string][]policy.Session{"once": once, "twice": twice} {
		if len(sessions) != 2 {
			t.Fatalf("%s: sessions=%d want 2: %+v", name, len(sessions), sessions)
		}
		if got := policy.Attribute(sessions, reconcileScope.CampusID, reconcileScope.AccessDomain, "10.0.0.1", base.Add(6*time.Hour+5*time.Minute)); got.State != "resolved" {
			t.Fatalf("%s: reopened session not active during its lifetime: %+v", name, got)
		}
	}
}

// The same holds when the new session starts exactly when the previous one ended.
func TestFoldKeepsSessionStartingAtPreviousEnd(t *testing.T) {
	base := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	first := snapshotRowAt("s", "a", "10.0.0.1", base)
	firstEnd := first
	firstEnd.Status, firstEnd.EndedAt, firstEnd.ConfirmedAt, firstEnd.Confirmations = "stop", base.Add(time.Hour), base.Add(time.Hour), nil
	login := eventRow("s", "a", "10.0.0.1", base.Add(time.Hour+time.Minute)) // starts at base+1h
	loginEnd := login
	loginEnd.Status, loginEnd.EndedAt, loginEnd.ConfirmedAt, loginEnd.Confirmations = "stop", base.Add(90*time.Minute), base.Add(90*time.Minute), nil
	twice := foldPolicySessions(foldPolicySessions([]policy.Session{first, firstEnd, login, loginEnd}))
	if len(twice) != 2 {
		t.Fatalf("sessions=%d want 2", len(twice))
	}
}
