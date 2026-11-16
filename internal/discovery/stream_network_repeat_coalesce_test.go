package discovery

import (
	"testing"
	"time"
)

func TestStreamNetworkRepeatCoalescesOnlyWithinSafeFreshnessWindow(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	base := streamDiscoveryFact{Epoch: "epoch-a", Device: "device-1", Key: "ssdp-router", Scope: "scope-a", Protocol: "ssdp", DeviceType: "router", Event: "event-a", EvidenceEvent: "event-a", FirstObserved: now.Add(-time.Minute), Observed: now.Add(-2 * time.Second), ValidUntil: now.Add(time.Minute), IP: "192.0.2.1"}
	previous, err := buildStreamDiscoveryState("epoch-a", base.Device, []streamDiscoveryFact{base}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	previous.Document = storedStreamNetworkDocument(t, previous.Document)
	repeat := base
	repeat.Event, repeat.Observed, repeat.ValidUntil = "event-b", now.Add(-time.Second), now.Add(time.Minute+time.Second)
	next, err := buildStreamDiscoveryState("epoch-a", repeat.Device, []streamDiscoveryFact{repeat}, &previous, now)
	if err != nil {
		t.Fatal(err)
	}
	coalesced := coalesceStreamDiscoveryStateFreshness(&previous, next, now)
	if !streamDiscoveryStateMatchesStored(previous, coalesced) || !coalesced.NetworkTypeLastSeen.Equal(previous.NetworkTypeLastSeen) || !coalesced.NetworkTypeValidUntil.Equal(previous.NetworkTypeValidUntil) {
		t.Fatalf("safe repeat rewrote network state: old=%+v next=%+v coalesced=%+v", previous, next, coalesced)
	}
	// The fact and receipt still carry the exact latest observation. Once the
	// bounded window elapses, the current-state lease and sparse index advance.
	repeat.Observed, repeat.ValidUntil = now.Add(4*time.Second), now.Add(2*time.Minute)
	later, err := buildStreamDiscoveryState("epoch-a", repeat.Device, []streamDiscoveryFact{repeat}, &previous, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	later = coalesceStreamDiscoveryStateFreshness(&previous, later, now.Add(4*time.Second))
	if streamDiscoveryStateMatchesStored(previous, later) || !later.NetworkTypeLastSeen.Equal(repeat.Observed) || !later.NetworkTypeValidUntil.Equal(repeat.ValidUntil) {
		t.Fatalf("network type lease was not renewed after bounded window: %+v", later)
	}
}

func TestStreamNetworkRepeatRenewsNearExpiryAndPreservesEvidenceChanges(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	base := streamDiscoveryFact{Epoch: "epoch-a", Device: "device-1", Key: "ssdp-router", Scope: "scope-a", Protocol: "ssdp", DeviceType: "gateway", Event: "event-a", EvidenceEvent: "event-a", FirstObserved: now.Add(-time.Minute), Observed: now.Add(-2 * time.Second), ValidUntil: now.Add(3 * time.Second)}
	previous, err := buildStreamDiscoveryState("epoch-a", base.Device, []streamDiscoveryFact{base}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	previous.Document = storedStreamNetworkDocument(t, previous.Document)
	repeat := base
	repeat.Event, repeat.Observed, repeat.ValidUntil = "event-b", now.Add(-time.Second), now.Add(time.Minute)
	next, err := buildStreamDiscoveryState("epoch-a", repeat.Device, []streamDiscoveryFact{repeat}, &previous, now)
	if err != nil {
		t.Fatal(err)
	}
	renewed := coalesceStreamDiscoveryStateFreshness(&previous, next, now)
	if streamDiscoveryStateMatchesStored(previous, renewed) || !renewed.NetworkTypeValidUntil.Equal(repeat.ValidUntil) {
		t.Fatalf("near-expiry network lease was not renewed: %+v", renewed)
	}
	// A visible evidence revision is a state change even inside the five-second
	// window; it must remain auditably linked to the new reference.
	base.ValidUntil = now.Add(time.Minute)
	previous, err = buildStreamDiscoveryState("epoch-a", base.Device, []streamDiscoveryFact{base}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	previous.Document = storedStreamNetworkDocument(t, previous.Document)
	repeat.ValidUntil = now.Add(2 * time.Minute)
	repeat.EvidenceEvent = "corrected-evidence"
	next, err = buildStreamDiscoveryState("epoch-a", repeat.Device, []streamDiscoveryFact{repeat}, &previous, now)
	if err != nil {
		t.Fatal(err)
	}
	renewed = coalesceStreamDiscoveryStateFreshness(&previous, next, now)
	if streamDiscoveryStateMatchesStored(previous, renewed) {
		t.Fatal("corrected evidence was hidden by network repeat coalescing")
	}
}

func TestStreamNetworkRepeatCoalescesWhenOtherFactOwnsDeviceLastSeen(t *testing.T) {
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	network := streamDiscoveryFact{Epoch: "epoch-a", Device: "device-1", Key: "ssdp-router", Scope: "scope-a", Protocol: "ssdp", DeviceType: "router", Event: "network-a", EvidenceEvent: "network-a", FirstObserved: now.Add(-time.Minute), Observed: now.Add(-2 * time.Second), ValidUntil: now.Add(time.Minute)}
	arp := streamDiscoveryFact{Epoch: "epoch-a", Device: "device-1", Key: "arp-binding", Scope: "scope-a", Protocol: "arp", Event: "arp-a", EvidenceEvent: "arp-a", FirstObserved: now.Add(-time.Minute), Observed: now, ValidUntil: now.Add(2 * time.Minute)}
	previous, err := buildStreamDiscoveryState("epoch-a", network.Device, []streamDiscoveryFact{network, arp}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	previous.Document = storedStreamNetworkDocument(t, previous.Document)
	network.Event, network.Observed, network.ValidUntil = "network-b", now.Add(-time.Second), now.Add(time.Minute+time.Second)
	next, err := buildStreamDiscoveryState("epoch-a", network.Device, []streamDiscoveryFact{network, arp}, &previous, now)
	if err != nil {
		t.Fatal(err)
	}
	coalesced := coalesceStreamDiscoveryStateFreshness(&previous, next, now)
	if !streamDiscoveryStateMatchesStored(previous, coalesced) {
		t.Fatalf("network heartbeat with unchanged device last_seen rewrote current state: %+v", coalesced)
	}
}

func storedStreamNetworkDocument(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	value, ok := streamDiscoveryJSONValue(document)
	if !ok {
		t.Fatal("cannot normalize network document")
	}
	return value.(map[string]any)
}
