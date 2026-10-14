package devicesignal

import (
	"net/netip"
	"testing"
	"time"
)

func stateKey(ip string, mac byte, ttl int) packetBucketKey {
	return packetBucketKey{IP: netip.MustParseAddr(ip), MAC: [6]byte{0x02, 0, 0, 0, 0, mac}, Direction: "inbound", TTL: ttl, Version: 4}
}

// The collector used to write every packet key every bucket: 66,795,351 device events in one
// day covered only 309,974 distinct states. A state that has not changed carries no device
// information, so it is written on first sighting and then at most once per liveness
// interval, with the folded packet count carried in that rewrite.
func TestStateChangeTrackerSuppressesUnchangedStates(t *testing.T) {
	const step = 30 * time.Second
	bucket := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	key := stateKey("10.0.0.1", 1, 64)
	packets := map[packetBucketKey]int{key: 3}

	if tracker := newStateChangeTracker(0); tracker != nil {
		t.Fatalf("liveness 0 must disable tracking, got %#v", tracker)
	}
	if got := (*stateChangeTracker)(nil).filter(bucket, packets); len(got) != 1 || got[key] != 3 {
		t.Fatalf("a disabled tracker must pass packets through: %#v", got)
	}

	tracker := newStateChangeTracker(5 * time.Minute)
	if got := tracker.filter(bucket, packets); len(got) != 1 || got[key] != 3 {
		t.Fatalf("a first sighting must be written at once: %#v", got)
	}
	for i := 1; i < 10; i++ {
		if got := tracker.filter(bucket.Add(time.Duration(i)*step), map[packetBucketKey]int{key: 2}); len(got) != 0 {
			t.Fatalf("bucket %d rewrote an unchanged state: %#v", i, got)
		}
	}
	// Ten buckets in, the liveness interval has elapsed: one rewrite carrying 9*2+2 packets.
	if got := tracker.filter(bucket.Add(10*step), map[packetBucketKey]int{key: 2}); len(got) != 1 || got[key] != 20 {
		t.Fatalf("liveness rewrite missing or miscounted: %#v", got)
	}
	if held := tracker.pending(); len(held) != 1 {
		t.Fatalf("shutdown must carry the held state, got %#v", held)
	}

	// A key that stays absent past the grace window is forgotten, so its return is a change.
	last := bucket.Add(10 * step)
	tracker.filter(last.Add(11*time.Minute), map[packetBucketKey]int{})
	if got := tracker.filter(last.Add(12*time.Minute), packetBucketKeyMap(key, 4)); len(got) != 1 || got[key] != 4 {
		t.Fatalf("a re-appearing state must be written again: %#v", got)
	}
	// But a key that is merely quiet for one bucket keeps its history: no re-report.
	quiet := stateKey("10.0.0.2", 2, 64)
	tracker.filter(bucket, map[packetBucketKey]int{quiet: 1})
	tracker.filter(bucket.Add(step), map[packetBucketKey]int{})
	if got := tracker.filter(bucket.Add(2*step), map[packetBucketKey]int{quiet: 1}); len(got) != 0 {
		t.Fatalf("a key quiet for one bucket was reported as new: %#v", got)
	}
}

func TestStateChangeTrackerBoundsTrackedKeys(t *testing.T) {
	const step = 30 * time.Second
	bucket := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	tracker := newStateChangeTracker(10 * time.Minute)
	tracker.limit = 2
	batch := map[packetBucketKey]int{
		stateKey("10.0.0.1", 1, 64): 1,
		stateKey("10.0.0.2", 2, 64): 1,
		stateKey("10.0.0.3", 3, 64): 1,
	}
	if got := tracker.filter(bucket, batch); len(got) != 2 {
		t.Fatalf("tracked key ceiling not enforced: wrote %d", len(got))
	}
	if tracker.dropped != 1 {
		t.Fatalf("dropped keys not counted: %d", tracker.dropped)
	}
	if tracker.trackedCount() != 2 {
		t.Fatalf("unexpected tracked count: %d", tracker.trackedCount())
	}
	// The ceiling does not block a later liveness rewrite of an already tracked key.
	if got := tracker.filter(bucket.Add(step), map[packetBucketKey]int{stateKey("10.0.0.1", 1, 64): 5}); len(got) != 0 {
		t.Fatalf("a still-present key was rewritten early: %#v", got)
	}
}

func packetBucketKeyMap(key packetBucketKey, count int) map[packetBucketKey]int {
	return map[packetBucketKey]int{key: count}
}
