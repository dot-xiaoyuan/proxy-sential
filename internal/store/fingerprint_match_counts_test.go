package store

import (
	"proxy-sentinel/internal/fingerprint"
	"sync"
	"testing"
	"time"
)

func TestFingerprintMatchCountsSeparateHistoryAndRelationships(t *testing.T) {
	var m fingerprintMatchMeter
	now := time.Now()
	matches := []fingerprint.SourceMatch{{SourceID: "recog", RuleID: "one"}, {SourceID: "recog", RuleID: "one"}, {SourceID: "satori", RuleID: "two"}}
	m.record(now, false, matches)
	m.record(now, false, matches)
	m.record(now, true, matches)
	got := m.take()
	if len(got) != 2 {
		t.Fatalf("buckets=%d", len(got))
	}
	for _, b := range got {
		if b.Realtime != 2 || b.History != 1 {
			t.Fatalf("bad counts: %+v", b)
		}
	}
	if len(m.take()) != 0 {
		t.Fatal("batch drained twice")
	}
	// Failed persistence restores the detached batch, without overwriting new work.
	m.record(now, false, matches)
	m.restore(got)
	for _, b := range m.take() {
		if b.Realtime != 3 || b.History != 1 {
			t.Fatalf("lost retry/concurrent counts: %+v", b)
		}
	}
}
func TestFingerprintMatchCountsExpireAndConcurrent(t *testing.T) {
	var m fingerprintMatchMeter
	now := time.Now()
	matches := []fingerprint.SourceMatch{{SourceID: "recog", RuleID: "one"}}
	m.record(now.Add(-25*time.Hour), false, matches)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.record(now, false, matches)
			}
		}()
	}
	wg.Wait()
	counts := m.take()
	if len(counts) != 1 {
		t.Fatalf("expired buckets retained: %d", len(counts))
	}
	for _, b := range counts {
		if b.Realtime != 1000 {
			t.Fatalf("concurrent count=%d", b.Realtime)
		}
	}
}
