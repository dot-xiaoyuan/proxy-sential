package store

import (
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestPassiveARPCoalescingKeepsFirstLastAndChangedFacts(t *testing.T) {
	arp := func(id, ip, mac, message string) normalized.Event {
		return normalized.Event{
			EventID: id, Source: "zeek", SourceEventType: "arp",
			Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
			Subject:  map[string]any{"ip": ip, "mac": mac, "campus_id": "campus-204"},
			Payload:  map[string]any{"origin": "arp", "message": message},
		}
	}
	events := []normalized.Event{
		arp("first", "10.1.1.2", "02:00:00:00:00:01", "reply"),
		arp("middle", "10.1.1.2", "02:00:00:00:00:01", "reply"),
		arp("last", "10.1.1.2", "02:00:00:00:00:01", "reply"),
		arp("other-message", "10.1.1.2", "02:00:00:00:00:01", "request"),
		arp("other-mac", "10.1.1.2", "02:00:00:00:00:02", "reply"),
		arp("other-ip", "10.1.1.3", "02:00:00:00:00:01", "reply"),
		arp("other-source", "10.1.1.2", "02:00:00:00:00:01", "reply"),
	}
	events[6].Source = "other"
	got := passiveCoalescedARPIndexes(events)
	if len(got) != 1 || !got[1] {
		t.Fatalf("only the unchanged middle ARP should be coalesced: %v", got)
	}
}

func TestPassiveARPCoalescingKeepsDifferentScopeAndOtherProtocols(t *testing.T) {
	base := normalized.Event{
		Source: "zeek", SourceEventType: "arp",
		Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
		Subject:  map[string]any{"ip": "10.1.1.2", "mac": "02:00:00:00:00:01", "campus_id": "campus-204"},
		Payload:  map[string]any{"origin": "arp", "message": "reply"},
	}
	events := []normalized.Event{base, base, base, base}
	events[1].Subject = map[string]any{"ip": "10.1.1.2", "mac": "02:00:00:00:00:01", "campus_id": "another-campus"}
	events[2].Observer = map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f1"}
	events[3].SourceEventType = "ndp"
	if got := passiveCoalescedARPIndexes(events); len(got) != 0 {
		t.Fatalf("scope changes and other protocols must be kept: %v", got)
	}
}
