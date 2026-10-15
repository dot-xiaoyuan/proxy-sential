package store

import (
	"testing"
	"time"
)

// An empty incremental pass used to persist its ten-minute overlap rewind, so the stored
// cursor walked backwards every five minutes until the seven-day floor. Replaying passes
// against an empty source must keep the cursor where it started.
func TestDomainReconcileEmptyPassesNeverRewindCursor(t *testing.T) {
	now := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	since := now.Add(-7 * 24 * time.Hour)
	stored, storedID := now.Add(-time.Hour), "evt-9"
	for pass := 0; pass < 50; pass++ {
		read, readID := domainReconcileStart("incremental", true, stored, storedID, since)
		if !read.Equal(stored.Add(-10 * time.Minute)) {
			t.Fatalf("pass %d read start %s, want ten-minute overlap", pass, read)
		}
		stored, storedID = domainReconcileHighWater(read, readID, stored, storedID)
	}
	if !stored.Equal(now.Add(-time.Hour)) || storedID != "evt-9" {
		t.Fatalf("empty passes moved the cursor to %s/%s", stored, storedID)
	}
}

func TestDomainReconcileHighWaterAdvancesWithProgress(t *testing.T) {
	high := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	if at, id := domainReconcileHighWater(high.Add(time.Second), "a", high, "z"); !at.Equal(high.Add(time.Second)) || id != "a" {
		t.Fatalf("progress not kept: %s %s", at, id)
	}
	if at, id := domainReconcileHighWater(high, "b", high, "a"); !at.Equal(high) || id != "b" {
		t.Fatalf("same-timestamp progress not kept: %s %s", at, id)
	}
	floor := high.Add(-time.Hour)
	if at, id := domainReconcileStart("daily", true, high, "x", floor); !at.Equal(floor) || id != "" {
		t.Fatalf("daily restart wrong: %s %s", at, id)
	}
}
