package store

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIdentityDeltaHistoricalIntervalEndsAtReplacement(t *testing.T) {
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	raw, _ := json.Marshal(map[string]any{"session_id": "s", "account_id": "old", "ip": "192.0.2.1", "first_confirmed_at": start.Format(time.RFC3339Nano), "ended_at": end.Format(time.RFC3339Nano)})
	m, err := projectionMemberFromRow(reconcileScope, end, raw)
	if err != nil || !m.First.Equal(start) || !m.End.Equal(end) {
		t.Fatalf("member=%+v err=%v", m, err)
	}
}
func TestIdentityDeltaAtomicGroupBound(t *testing.T) {
	rows := make([]identityDeltaMember, 501)
	for i := range rows {
		rows[i] = identityDeltaMember{IP: "192.0.2.1", Document: json.RawMessage(`{}`)}
	}
	if _, err := identityDeltaBatch(rows, 100, 1<<20); err == nil {
		t.Fatal("oversized single IP must not be truncated")
	}
}
