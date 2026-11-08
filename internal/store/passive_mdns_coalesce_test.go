package store

import (
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestPassiveMDNSCoalescingPreservesEdgesAndWithdrawal(t *testing.T) {
	record := func(id, sender, address string, ttl int) normalized.Event {
		return normalized.Event{EventID: id, SourceEventType: "mdns", Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"}, Subject: map[string]any{"ip": sender}, Payload: map[string]any{"is_response": true, "record_type": "A", "record_name": "printer.local", "record_address": address, "ttl": ttl}}
	}
	events := []normalized.Event{
		record("first", "192.168.1.2", "192.168.1.2", 120),
		record("middle", "192.168.1.2", "192.168.1.2", 120),
		record("last", "192.168.1.2", "192.168.1.2", 120),
		record("other-sender", "192.168.1.3", "192.168.1.2", 120),
		record("withdraw", "192.168.1.2", "192.168.1.2", 0),
		record("new-first", "192.168.1.2", "192.168.1.2", 120),
		record("new-last", "192.168.1.2", "192.168.1.2", 120),
		record("other-value", "192.168.1.2", "192.168.1.4", 120),
	}
	coalesced := passiveCoalescedMDNSIndexes(events)
	if len(coalesced) != 1 || !coalesced[1] {
		t.Fatalf("expected only middle repeat to be coalesced, got %v", coalesced)
	}
}

func TestPassiveMDNSCoalescingKeepsChangedContentAndQueries(t *testing.T) {
	events := []normalized.Event{
		{SourceEventType: "mdns", Observer: map[string]any{"sensor_id": "s"}, Payload: map[string]any{"is_response": true, "record_type": "TXT", "record_name": "printer._ipp._tcp.local", "record_text": "product=A", "ttl": 120}},
		{SourceEventType: "mdns", Observer: map[string]any{"sensor_id": "s"}, Payload: map[string]any{"is_response": true, "record_type": "TXT", "record_name": "printer._ipp._tcp.local", "record_text": "product=B", "ttl": 120}},
		{SourceEventType: "mdns", Observer: map[string]any{"sensor_id": "s"}, Payload: map[string]any{"is_response": false, "record_type": "TXT", "record_name": "printer._ipp._tcp.local", "record_text": "product=A", "ttl": 120}},
	}
	if got := passiveCoalescedMDNSIndexes(events); len(got) != 0 {
		t.Fatalf("changed content or query was coalesced: %v", got)
	}
}

func TestPassiveMDNSCoalescingKeepsDifferentDirectResponders(t *testing.T) {
	record := func(id, mac string) normalized.Event {
		return normalized.Event{EventID: id, SourceEventType: "mdns", Observer: map[string]any{"sensor_id": "s"}, Subject: map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"is_response": true, "record_type": "PTR", "record_name": "_ipp._tcp.local", "service_target": "printer._ipp._tcp.local", "responder_l2_mac": mac, "l2_source_mac_direct": true, "ttl": 120}}
	}
	events := []normalized.Event{record("a", "02:00:00:00:00:01"), record("b", "02:00:00:00:00:02"), record("c", "02:00:00:00:00:01")}
	if got := passiveCoalescedMDNSIndexes(events); len(got) != 0 {
		t.Fatalf("different direct responders were coalesced: %v", got)
	}
}
