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
	if got := classifyInventoryProjection(sql.NullTime{}, false, now); got.Status != "ready" {
		t.Fatalf("empty queue: %s", got.Status)
	}
	if got := classifyInventoryProjection(sql.NullTime{Time: now.Add(-13 * time.Hour), Valid: true}, false, now); got.Status != "stale" {
		t.Fatalf("13h backlog: %s", got.Status)
	}
	if got := classifyInventoryProjection(sql.NullTime{}, true, now); got.Status != "failed" {
		t.Fatalf("failed endpoints hidden: %s", got.Status)
	}
}
