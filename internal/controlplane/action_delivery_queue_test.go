package controlplane

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestActionDeliveryQueueBoundsWorkersAndPreservesOverflowForRetry(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var running, peak, calls atomic.Int32
	var completed sync.WaitGroup
	completed.Add(130)
	q := newActionDeliveryQueue(func(id string, revoke bool) {
		defer completed.Done()
		current := running.Add(1)
		defer running.Add(-1)
		for old := peak.Load(); current > old && !peak.CompareAndSwap(old, current); old = peak.Load() {
		}
		if id == "first" || id == "second" {
			entered <- struct{}{}
		}
		<-release
		calls.Add(1)
	})
	if !q.submit("first", false) || !q.submit("second", true) {
		t.Fatal("initial durable intents were not accepted")
	}
	<-entered
	<-entered
	for i := 0; i < 128; i++ {
		if !q.submit(fmt.Sprintf("queued-%d", i), false) {
			t.Fatal("bounded queue rejected available slot")
		}
	}
	if !q.submit("first", false) {
		t.Fatal("duplicate running intent was not coalesced")
	}
	if q.submit("overflow", false) {
		t.Fatal("queue exceeded its bound")
	}
	q.mu.Lock()
	retained := q.active["overflow"]
	q.mu.Unlock()
	if retained {
		t.Fatal("overflow intent was marked active, preventing scheduler retry")
	}
	close(release)
	completed.Wait()
	close(q.queue)
	if peak.Load() != 2 || calls.Load() != 130 {
		t.Fatalf("unbounded or repeated external calls: peak=%d calls=%d", peak.Load(), calls.Load())
	}
}
