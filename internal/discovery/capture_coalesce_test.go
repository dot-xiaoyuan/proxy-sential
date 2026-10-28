package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestCaptureCoalescerKeepsBoundedRepeatEvidence(t *testing.T) {
	first := streamDiscoveryEvent("first", "2026-10-28T10:00:00Z", 120)
	last := streamDiscoveryEvent("last", "2026-10-28T10:00:00.8Z", 180)
	c := newCaptureCoalescer()
	if c.add(first) || !c.add(last) {
		t.Fatal("positive-TTL repeat was not combined")
	}
	events := c.drain()
	if len(events) != 1 || events[0].EventID != "last" || events[0].RawRef["coalesced_count"] != 2 ||
		events[0].RawRef["coalesced_first_observed_at"] != first.Timestamp ||
		events[0].RawRef["coalesced_first_producer_event_id"] != first.EventID ||
		events[0].Payload["ttl"] != 180 {
		t.Fatalf("repeat lost first/last/count or renewal: %+v", events)
	}
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", AcceptedAt: time.Date(2026, 10, 28, 10, 0, 1, 0, time.UTC), Events: events}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].Fact.FirstObserved.Format(time.RFC3339Nano) != first.Timestamp ||
		prepared[0].Fact.Observed.Format(time.RFC3339Nano) != last.Timestamp ||
		prepared[0].Fact.ValidUntil.Sub(prepared[0].Fact.Observed) != 180*time.Second {
		t.Fatalf("projected freshness differs from coalesced observation: %+v %v", prepared, err)
	}
}

func TestCaptureCoalescerPreservesScopeChangesWithdrawalsAndLateInputs(t *testing.T) {
	base := streamDiscoveryEvent("base", "2026-10-28T10:00:00Z", 120)
	otherScope := streamDiscoveryEvent("other-scope", "2026-10-28T10:00:00.1Z", 120)
	otherScope.Observer["source_id"] = "another-source"
	otherScope.Subject["vlan"] = "992"
	withdrawn := streamDiscoveryEvent("withdrawn", "2026-10-28T10:00:00.2Z", 0)
	corrected := streamDiscoveryEvent("corrected", "2026-10-28T10:00:00.3Z", 120)
	corrected.Payload["txt"] = "ty=Different Model"
	late := streamDiscoveryEvent("late", "2026-10-28T09:59:59Z", 120)
	outsideWindow := streamDiscoveryEvent("outside-window", "2026-10-28T10:00:02Z", 120)
	c := newCaptureCoalescer()
	c.add(base)
	for _, event := range []normalized.Event{otherScope, withdrawn, corrected, late, outsideWindow} {
		if c.add(event) {
			t.Fatalf("distinct event was combined: %s", event.EventID)
		}
	}
	if got := len(c.drain()); got != 6 {
		t.Fatalf("distinct observations lost: %d", got)
	}
}
