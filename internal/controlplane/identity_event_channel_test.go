package controlplane

import (
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestAccountingChannelRequiresFreshLifecycleWithoutInventingHeartbeat(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		action string
		stamp  time.Time
		want   bool
	}{{"start", now, true}, {"stop", now, true}, {"interim", now, true}, {"reconcile", now, false}, {"start", now.Add(-time.Hour), false}, {"start", now.Add(time.Hour), false}} {
		event := normalized.Event{Type: "identity", Timestamp: tc.stamp.Format(time.RFC3339Nano), Subject: map[string]any{"account_id": "a"}, Payload: map[string]any{"action": tc.action, "session_id": "s"}}
		if got := hasRecentAccountingLifecycle([]normalized.Event{event}, now); got != tc.want {
			t.Fatalf("action=%s time=%s healthy=%v", tc.action, tc.stamp, got)
		}
	}
}
