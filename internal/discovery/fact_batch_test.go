package discovery

import (
	"testing"
	"time"
)

func TestDiscoveryFactVersionOrdering(t *testing.T) {
	at := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	current := discoveryFactVersion{Event: "b", Revision: 0, Observed: at}
	for _, tc := range []struct {
		name string
		next discoveryFactVersion
		want bool
	}{
		{"repeat", discoveryFactVersion{Event: "b", Revision: 0, Observed: at.Add(time.Hour)}, false},
		{"correction", discoveryFactVersion{Event: "b", Revision: 1, Observed: at.Add(-time.Hour)}, true},
		{"older_revision", discoveryFactVersion{Event: "b", Revision: -1, Observed: at.Add(time.Hour)}, false},
		{"later_event", discoveryFactVersion{Event: "a", Observed: at.Add(time.Second)}, true},
		{"late_event", discoveryFactVersion{Event: "z", Observed: at.Add(-time.Second)}, false},
		{"tie_break_wins", discoveryFactVersion{Event: "c", Observed: at}, true},
		{"tie_break_loses", discoveryFactVersion{Event: "a", Observed: at}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := current.supersededBy(tc.next); got != tc.want {
				t.Fatalf("superseded=%v want=%v", got, tc.want)
			}
		})
	}
}
