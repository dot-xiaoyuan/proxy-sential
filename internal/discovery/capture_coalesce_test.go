package discovery

import (
	"context"
	"strings"
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

func TestCaptureCoalescerPreservesInterleavedTransitions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		middle func(normalized.Event) normalized.Event
	}{
		{"withdrawal", func(e normalized.Event) normalized.Event { e.Payload["ttl"] = 0; return e }},
		{"correction", func(e normalized.Event) normalized.Event { e.Payload["txt"] = "ty=Changed"; return e }},
		{"other scope", func(e normalized.Event) normalized.Event { e.Subject["vlan"] = "other"; return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCaptureCoalescer()
			first := streamDiscoveryEvent("first", "2026-10-28T10:00:00Z", 120)
			middle := tc.middle(streamDiscoveryEvent("middle", "2026-10-28T10:00:00.2Z", 120))
			last := streamDiscoveryEvent("last", "2026-10-28T10:00:00.4Z", 120)
			c.add(first)
			c.add(middle)
			c.add(last)
			got := c.drain()
			if len(got) != 3 || got[0].EventID != "first" || got[1].EventID != "middle" || got[2].EventID != "last" {
				ids := make([]string, 0, len(got))
				for _, e := range got {
					ids = append(ids, e.EventID)
				}
				t.Fatalf("interleaved events lost ordering: %v", ids)
			}
		})
	}
}

func TestCaptureCoalescerWithdrawalAndRestoreReachProjection(t *testing.T) {
	c := newCaptureCoalescer()
	c.add(streamDiscoveryEvent("first", "2026-10-28T10:00:00Z", 120))
	c.add(streamDiscoveryEvent("withdrawn", "2026-10-28T10:00:00.2Z", 0))
	c.add(streamDiscoveryEvent("restored", "2026-10-28T10:00:00.4Z", 120))
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", AcceptedAt: time.Date(2026, 10, 28, 10, 0, 1, 0, time.UTC), Events: c.drain()}
	items, err := prepareStreamDiscovery(segment)
	if err != nil || len(items) != 3 {
		t.Fatalf("prepare transition sequence: %v %v", items, err)
	}
	withdraw := mergeStreamDiscoveryFact(&items[0].Fact, items[1].Fact)
	restore := mergeStreamDiscoveryFact(&items[1].Fact, items[2].Fact)
	if withdraw.Result != "withdrawn" || !withdraw.VisibleChanged || restore.Result != "restored" || !restore.VisibleChanged {
		t.Fatalf("withdrawal or restoration missing: %+v %+v", withdraw, restore)
	}
}

func TestCaptureCoalescerPreservesInvalidTTLObservations(t *testing.T) {
	for _, tc := range []struct {
		name              string
		firstTTL, lastTTL int
		invalidIndex      int
	}{
		{"invalid_then_valid", 604801, 120, 0},
		{"valid_then_invalid", 120, 604801, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCaptureCoalescer()
			first := streamDiscoveryEvent("first", "2026-10-28T10:00:00Z", tc.firstTTL)
			last := streamDiscoveryEvent("last", "2026-10-28T10:00:00.5Z", tc.lastTTL)
			c.add(first)
			if c.add(last) {
				t.Fatal("invalid TTL was collapsed with a valid observation")
			}
			segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", AcceptedAt: time.Date(2026, 10, 28, 10, 0, 1, 0, time.UTC), Events: c.drain()}
			items, err := prepareStreamDiscovery(segment)
			if err != nil || len(items) != 2 {
				t.Fatalf("lost input: items=%d err=%v", len(items), err)
			}
			if items[tc.invalidIndex].Parsed || !strings.Contains(items[tc.invalidIndex].Receipt.Result, "invalid TTL") || !items[1-tc.invalidIndex].Parsed {
				t.Fatalf("invalid or valid input hidden: %+v %+v", items[0].Receipt, items[1].Receipt)
			}
		})
	}
}

func TestCaptureCoalescerDoesNotBridgeTTLExpiration(t *testing.T) {
	c := newCaptureCoalescer()
	first := streamDiscoveryEvent("first", "2026-10-28T10:00:00Z", 1)
	last := streamDiscoveryEvent("last", "2026-10-28T10:00:01Z", 120)
	c.add(first)
	if c.add(last) {
		t.Fatal("observations separated by an expiry were combined")
	}
	got := c.drain()
	if len(got) != 2 || got[0].EventID != "first" || got[1].EventID != "last" {
		t.Fatalf("expiry boundary lost: %+v", got)
	}
}

func TestCaptureCoalescerPreservesEqualTimestampConflictOrdering(t *testing.T) {
	first := streamDiscoveryEvent("z", "2026-10-28T10:00:00Z", 120)
	last := streamDiscoveryEvent("a", "2026-10-28T10:00:00Z", 180)
	c := newCaptureCoalescer()
	c.add(first)
	if c.add(last) {
		t.Fatal("equal-time events with different validity were combined")
	}
	segment := streamlog.Segment{Epoch: "fresh", Source: "passive-discovery", AcceptedAt: time.Date(2026, 10, 28, 10, 0, 1, 0, time.UTC), Events: c.drain()}
	items, err := prepareStreamDiscovery(segment)
	if err != nil || len(items) != 2 {
		t.Fatalf("lost equal-time input: %d %v", len(items), err)
	}
	decision := mergeStreamDiscoveryFact(&items[0].Fact, items[1].Fact)
	if decision.Result != "late_history" || decision.WriteFact {
		t.Fatalf("event-key tie-break lost: %+v", decision)
	}
	if items[0].Fact.ValidUntil.Sub(items[0].Fact.Observed) != 120*time.Second {
		t.Fatal("winning validity changed")
	}
}

func TestEqualTimestampTieSurvivesPassiveSourceIdentityAssignment(t *testing.T) {
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := PassiveStreamSourcePath(source)
	if err = j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-4", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	first := streamDiscoveryEvent("first", at.Format(time.RFC3339Nano), 120)
	last := streamDiscoveryEvent("last", at.Format(time.RFC3339Nano), 180)
	for _, event := range []*normalized.Event{&first, &last} {
		event.Observer["capture_scope_id"] = ""
		event.Observer["interface"] = "bond0"
		event.Subject["site"] = "site-a"
		event.Subject["domain"] = "domain-a"
	}
	c := newCaptureCoalescer()
	c.add(first)
	if c.add(last) {
		t.Fatal("same-time inputs were collapsed")
	}
	id, err := AppendPassiveStreamBatch(context.Background(), j, source, scope, c.drain())
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || len(state.Segment.Events) != 2 {
		t.Fatalf("source receipt lost input: %v %v", len(state.Segment.Events), err)
	}
	if state.Segment.Events[0].EventID <= state.Segment.Events[1].EventID {
		t.Fatal("fixture must exercise descending generated event-key tie")
	}
	items, err := prepareStreamDiscovery(state.Segment)
	if err != nil || len(items) != 2 {
		t.Fatalf("prepare source events: %v", err)
	}
	decision := mergeStreamDiscoveryFact(&items[0].Fact, items[1].Fact)
	if decision.Result != "late_history" || decision.WriteFact || items[0].Fact.ValidUntil.Sub(items[0].Fact.Observed) != 120*time.Second {
		t.Fatalf("source tie changed winning validity: %+v", decision)
	}
}
