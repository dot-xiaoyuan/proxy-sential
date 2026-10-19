package policy

import (
	"testing"
	"time"
)

// A confirmed range stands for consecutive confirmations: any time inside it is confirmed, and the
// session is not active outside both its confirmations and its ranges.
func TestStateHonoursConfirmedRanges(t *testing.T) {
	base := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	s := Session{ID: "s", AccountID: "a", Source: "src", StartedAt: base, ConfirmedAt: base.Add(5 * time.Hour), HeartbeatSeconds: 1800,
		Confirmations:   []time.Time{base, base.Add(5 * time.Hour)},
		ConfirmedRanges: []IdentityCoverage{{From: base.Add(30 * time.Minute), To: base.Add(3*time.Hour + 30*time.Minute)}}}
	for _, c := range []struct {
		at   time.Duration
		want string
	}{{time.Hour, "active"}, {3 * time.Hour, "active"}, {4 * time.Hour, "unknown"}, {5*time.Hour + time.Minute, "active"}} {
		if got := s.State(base.Add(c.at)); got != c.want {
			t.Fatalf("at +%s state=%s want %s", c.at, got, c.want)
		}
	}
}
