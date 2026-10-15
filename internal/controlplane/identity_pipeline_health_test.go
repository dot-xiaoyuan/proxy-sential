package controlplane

import (
	"database/sql"
	"testing"
	"time"
)

// A reachable database is not progress. The inbox must report delayed, stale or failed
// from its backlog age so a stalled pipeline is visible on /readyz.
func TestIdentityPipelineHealthReflectsBacklogAge(t *testing.T) {
	now := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	at := func(age time.Duration) sql.NullTime { return sql.NullTime{Time: now.Add(-age), Valid: true} }
	cases := []struct {
		pending int64
		oldest  sql.NullTime
		err     string
		want    string
	}{
		{0, sql.NullTime{}, "", "ready"},
		{10, at(2 * time.Second), "", "ready"},
		{10, at(30 * time.Second), "", "delayed"},
		{62084, at(150 * time.Minute), "", "stale"},
		{62084, at(150 * time.Minute), "identity_processing_failed", "failed"},
	}
	for _, c := range cases {
		if got := classifyIdentityPipeline(c.pending, c.oldest, c.err, now); got.Status != c.want {
			t.Fatalf("pending=%d age=%v err=%q: got %s want %s", c.pending, c.oldest, c.err, got.Status, c.want)
		}
	}
}

func TestInventoryProjectionHealthReportsAgeAndFailures(t *testing.T) {
	now := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	at := func(age time.Duration) sql.NullTime { return sql.NullTime{Time: now.Add(-age), Valid: true} }
	if got := classifyInventoryProjection(at(20*time.Second), false, now); got.Status != "ready" {
		t.Fatalf("recent round: %s", got.Status)
	}
	if got := classifyInventoryProjection(at(2*time.Minute), false, now); got.Status != "delayed" {
		t.Fatalf("2m old round: %s", got.Status)
	}
	if got := classifyInventoryProjection(at(13*time.Hour), false, now); got.Status != "stale" {
		t.Fatalf("13h old round: %s", got.Status)
	}
	if got := classifyInventoryProjection(sql.NullTime{}, false, now); got.Status != "stale" {
		t.Fatalf("never ran: %s", got.Status)
	}
	if got := classifyInventoryProjection(at(10*time.Second), true, now); got.Status != "failed" {
		t.Fatalf("failed round hidden: %s", got.Status)
	}
}
