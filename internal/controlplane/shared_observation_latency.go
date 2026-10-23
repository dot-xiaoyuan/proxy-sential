package controlplane

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const sharedLatencyWindow = 15 * time.Minute
const sharedLatencyCapacity = 131072

type sharedLatencySample struct {
	at time.Time
	ms int64
}

// Successful commits, including repeated decisions for a subject, are sampled
// after Commit returns. The bounded ring exposes overflow rather than silently
// claiming a complete percentile when throughput exceeds its capacity.
type sharedDecisionLatencyWindow struct {
	mu              sync.Mutex
	items           []sharedLatencySample
	next            int
	incompleteUntil time.Time
}

var sharedDecisionLatencies sharedDecisionLatencyWindow
var sharedObservationFailures atomic.Int64
var sharedObservationVersionConflicts atomic.Int64

func (w *sharedDecisionLatencyWindow) record(at time.Time, latency time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := sharedLatencySample{at, max(0, latency.Milliseconds())}
	if len(w.items) < sharedLatencyCapacity {
		w.items = append(w.items, s)
		return
	}
	old := w.items[w.next]
	if old.at.Add(sharedLatencyWindow).After(at) {
		w.incompleteUntil = old.at.Add(sharedLatencyWindow)
	}
	w.items[w.next] = s
	w.next = (w.next + 1) % sharedLatencyCapacity
}

func (w *sharedDecisionLatencyWindow) snapshot(at time.Time) (int64, float64) {
	w.mu.Lock()
	values := make([]int64, 0, len(w.items))
	for _, s := range w.items {
		if !s.at.Before(at.Add(-sharedLatencyWindow)) && !s.at.After(at) {
			values = append(values, s.ms)
		}
	}
	incomplete := at.Before(w.incompleteUntil)
	w.mu.Unlock()
	if incomplete {
		return int64(len(values)), -1 // explicitly unavailable, never a passing P99
	}
	if len(values) == 0 {
		return 0, 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return int64(len(values)), float64(values[int(math.Ceil(float64(len(values))*.99))-1])
}
