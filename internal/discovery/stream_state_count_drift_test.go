package discovery

import (
	"testing"
	"time"
)

// A stored evidence count that drifted from a complete fact read used to fail
// the whole segment and deadlock the ordered projection lane. The resolved
// count must follow the committed facts instead.
func TestStreamStateTotalCountRepairsCompleteReadDrift(t *testing.T) {
	total, drift := streamStateTotalCount(89, 0, 90, false)
	if !drift || total != 90 {
		t.Fatalf("complete read must repair drift: total=%d drift=%t", total, drift)
	}
	total, drift = streamStateTotalCount(90, 1, 91, false)
	if drift || total != 91 {
		t.Fatalf("matching count must stay as stored plus new: total=%d drift=%t", total, drift)
	}
}

// A truncated read only carries the bounded subset, so the stored count plus
// the new facts remains authoritative.
func TestStreamStateTotalCountKeepsStoredCountForTruncatedRead(t *testing.T) {
	total, drift := streamStateTotalCount(300, 2, 257, true)
	if drift || total != 302 {
		t.Fatalf("truncated read must keep the stored count: total=%d drift=%t", total, drift)
	}
}

// The repaired count must be accepted by the summary builder so the segment can
// commit instead of retrying forever.
func TestBuildStreamDiscoveryStateAcceptsRepairedCount(t *testing.T) {
	now := time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)
	prior := streamDiscoveryState{
		Epoch: "fresh", Device: "device-1", Scope: "scope-1",
		FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Minute),
		Document: map[string]any{"evidence_count": float64(89)},
	}
	facts := make([]streamDiscoveryFact, 90)
	for i := range facts {
		facts[i] = streamDiscoveryFact{
			Epoch: "fresh", Device: "device-1", Key: "fact-" + itoa(i), Scope: "scope-1",
			Event: "event-" + itoa(i), Protocol: "arp", IP: "10.2.3." + itoa(i%250),
			Observed: now.Add(-time.Minute), FirstObserved: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute),
		}
	}
	if _, err := buildStreamDiscoveryStateSummary("fresh", "device-1", facts, &prior, now, 89, false, nil, nil); err == nil {
		t.Fatal("a stale count passed straight to the summary builder must still fail closed")
	}
	total, drift := streamStateTotalCount(89, 0, len(facts), false)
	if !drift {
		t.Fatal("expected drift to be reported")
	}
	state, err := buildStreamDiscoveryStateSummary("fresh", "device-1", facts, &prior, now, total, false, nil, nil)
	if err != nil {
		t.Fatalf("repaired count rejected: %v", err)
	}
	if got, ok := streamDiscoveryEvidenceCount(state.Document); !ok || got != 90 {
		t.Fatalf("repaired evidence count = %v (ok=%t), want 90", got, ok)
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := [12]byte{}
	pos := len(digits)
	for value > 0 {
		pos--
		digits[pos] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[pos:])
}
