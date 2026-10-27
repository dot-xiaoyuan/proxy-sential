package store

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdentityDerivedQuotaKeepsRealtimePriorityAndEventuallyAdmits(t *testing.T) {
	var last atomic.Int64
	started := time.Unix(100, 0)
	if identityDerivedQuotaAllow(&last, started) {
		t.Fatal("first busy check bypassed realtime gate")
	}
	if identityDerivedQuotaAllow(&last, started.Add(identityDerivedQuotaInterval-time.Nanosecond)) {
		t.Fatal("quota admitted before the ten-second interval")
	}
	if !identityDerivedQuotaAllow(&last, started.Add(identityDerivedQuotaInterval)) {
		t.Fatal("quota did not admit bounded low-priority work")
	}
}

func TestIdentityDerivedQuotaIsSharedAcrossWorkers(t *testing.T) {
	var last atomic.Int64
	started := time.Unix(100, 0)
	if identityDerivedQuotaAllow(&last, started) {
		t.Fatal("first busy check bypassed realtime gate")
	}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if identityDerivedQuotaAllow(&last, started.Add(identityDerivedQuotaInterval)) {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("concurrent workers admitted %d slots, want one", got)
	}
}
