package controlplane

import (
	"testing"
	"time"
)

func TestSharedLatencyCountsCompletionsAndDropsOldSamples(t *testing.T) {
	var samples sharedDecisionLatencyWindow
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	samples.record(now.Add(-16*time.Minute), time.Hour)
	// Repeated completions for the same IP must all count; expiry is excluded
	// at the caller, not substituted for a previous decision's latency.
	for i := 0; i < 100; i++ {
		samples.record(now, time.Duration(i+1)*time.Millisecond)
	}
	n, p99 := samples.snapshot(now)
	if n != 100 || p99 != 99 {
		t.Fatalf("count=%d p99=%v", n, p99)
	}
	n, p99 = samples.snapshot(now.Add(16 * time.Minute))
	if n != 0 || p99 != 0 {
		t.Fatalf("expired samples retained: count=%d p99=%v", n, p99)
	}
}
