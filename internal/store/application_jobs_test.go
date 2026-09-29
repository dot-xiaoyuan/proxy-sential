package store

import (
	"proxy-sentinel/internal/appdomain"
	"testing"
	"time"
)

func TestApplicationJobUpperBoundLeavesRoomForLateRealtimeEvents(t *testing.T) {
	now := time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)
	if got := applicationJobUpperBound("realtime", now); !got.Equal(now.Add(-15 * time.Second)) {
		t.Fatalf("unexpected realtime upper bound: %s", got)
	}
	if got := applicationJobUpperBound("history", now); !got.Equal(now) {
		t.Fatalf("history upper bound must stay exact: %s", got)
	}
}

func TestApplicationRealtimeScanWindowIsBounded(t *testing.T) {
	if applicationRealtimeScanSeconds != 60 {
		t.Fatalf("unexpected realtime scan window: %d", applicationRealtimeScanSeconds)
	}
}

func TestApplicationRealtimeDeduplicationOnlyForExplicitReplayRange(t *testing.T) {
	now := time.Date(2026, time.September, 28, 8, 30, 0, 0, time.UTC)
	scan := appdomain.Scan{From: now.Add(-time.Minute), To: now}
	if applicationNeedsExistingLookup("realtime", appdomain.Job{}, scan) {
		t.Fatal("ordinary monotonic realtime processing must not scan retained observations")
	}
	job := appdomain.Job{DeduplicateUntil: now.Add(-30 * time.Second)}
	if !applicationNeedsExistingLookup("realtime", job, scan) {
		t.Fatal("explicit realtime replay range must preserve idempotency lookup")
	}
	if !applicationNeedsExistingLookup("history", appdomain.Job{}, scan) {
		t.Fatal("history processing must preserve idempotency lookup")
	}
}
