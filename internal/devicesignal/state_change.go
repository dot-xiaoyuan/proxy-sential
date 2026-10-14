package devicesignal

import "time"

// stateChangeTracker suppresses device reports that only restate a state the collector has
// already written.
//
// Field measurement (184, 2026-10-14): 66,795,351 device events in one day covered only
// 309,974 distinct (ip,mac) states — 215 reports per state — and two MACs alone produced
// 49% of the volume at 178-202 reports per second. Every bucket re-emitted every packet key
// with an identical identity tuple, changing only the timestamp and the per-bucket packet
// count, and `observed_count` is read by no consumer in the process. A record whose only
// difference from the previous one is its timestamp carries no device information.
//
// New keys are written immediately, because a new (ip,mac,ttl,tcp) binding is real
// information. Keys that stay present are rewritten once per liveness interval so that
// last_seen keeps a known granularity. Keys that stop appearing age out, so a later
// re-appearance is reported again as a change.
type stateChangeTracker[K comparable] struct {
	liveness time.Duration
	grace    time.Duration
	limit    int
	active   map[K]*stateEntry
	dropped  int
}

// maxTrackedStateKeys bounds the cross-bucket working set. It is larger than one bucket's
// key ceiling because keys are retained across buckets.
const maxTrackedStateKeys = 200000

type stateEntry struct {
	firstSeen time.Time
	lastSeen  time.Time
	emitted   time.Time
	count     int
}

func newStateChangeTracker[K comparable](liveness time.Duration) *stateChangeTracker[K] {
	if liveness <= 0 {
		return nil
	}
	return &stateChangeTracker[K]{
		liveness: liveness,
		grace:    liveness,
		limit:    maxTrackedStateKeys,
		active:   map[K]*stateEntry{},
	}
}

// filter returns the subset of this bucket's packets that must be written now. Everything
// else is folded into its tracked entry and written by a later bucket.
func (t *stateChangeTracker[K]) filter(bucket time.Time, packets map[K]int) map[K]int {
	if t == nil || len(packets) == 0 {
		return packets
	}
	out := make(map[K]int)
	for key, count := range packets {
		entry, tracked := t.active[key]
		if !tracked {
			if len(t.active) >= t.limit {
				t.dropped++
				continue
			}
			// The first sighting is written now, so the entry starts with an empty
			// accumulator rather than double-counting this bucket's packets.
			t.active[key] = &stateEntry{firstSeen: bucket, lastSeen: bucket, emitted: bucket}
			out[key] = count
			continue
		}
		entry.count += count
		entry.lastSeen = bucket
		if bucket.Sub(entry.emitted) >= t.liveness {
			out[key] = entry.count
			entry.count = 0
			entry.emitted = bucket
		}
	}
	for key, entry := range t.active {
		if bucket.Sub(entry.lastSeen) > t.grace {
			delete(t.active, key)
		}
	}
	return out
}

// pending returns every still-tracked key so a shutdown writes the state it holds.
func (t *stateChangeTracker[K]) pending() map[K]int {
	if t == nil || len(t.active) == 0 {
		return nil
	}
	out := make(map[K]int, len(t.active))
	for key, entry := range t.active {
		out[key] = entry.count
	}
	return out
}

// trackedCount reports how many keys the tracker is holding, for the periodic diagnostics.
func (t *stateChangeTracker[K]) trackedCount() int {
	if t == nil {
		return 0
	}
	return len(t.active)
}

// selectControls applies the same rule to control signals (SSDP, LLDP, IEEE1905, ...). The
// field sample showed one gateway IP advertising 144 distinct payloads inside a single
// bucket — 140 distinct USNs, i.e. many real services relayed behind one address — and every
// one of them re-advertised each bucket. A service that has not changed since it was last
// written is not re-written until the liveness interval elapses.
func selectControls(t *stateChangeTracker[string], bucket time.Time, values map[string]controlSignal) map[string]controlSignal {
	if t == nil || len(values) == 0 {
		return values
	}
	counted := make(map[string]int, len(values))
	for key := range values {
		counted[key] = 1
	}
	keep := t.filter(bucket, counted)
	if len(keep) == 0 {
		return nil
	}
	out := make(map[string]controlSignal, len(keep))
	for key, signal := range values {
		if _, wanted := keep[key]; wanted {
			out[key] = signal
		}
	}
	return out
}
