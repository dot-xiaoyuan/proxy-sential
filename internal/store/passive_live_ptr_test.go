package store

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func passiveLivePTRTestEvent(id string, at time.Time, ttl int) normalized.Event {
	return normalized.Event{
		EventID: id, Source: "zeek", SourceEventType: "mdns", Timestamp: at.Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
		Subject:  map[string]any{"ip": "10.1.1.24", "campus_id": "campus-204"},
		Flow:     map[string]any{"src_ip": "10.1.1.24", "dst_ip": "224.0.0.251"},
		Payload:  map[string]any{"is_response": true, "record_type": "PTR", "record_name": "_ipp._tcp.local", "service_target": "HP LaserJet Pro._ipp._tcp.local", "record_ttl": ttl, "l2_source_mac_direct": true, "responder_l2_mac": "02:00:00:00:00:24"},
	}
}

func TestPassiveLivePTRRequiresDirectMulticastResponder(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	at := time.Now().UTC().Truncate(time.Second)
	event := passiveLivePTRTestEvent("ptr-valid", at, 120)
	got, ok := passiveLivePTRFact(event, scope)
	if !ok || got.EndpointID != "mac:02:00:00:00:00:24" || got.Name != "HP LaserJet Pro" || got.Withdrawn || !got.ValidUntil.Equal(at.Add(120*time.Second)) {
		t.Fatalf("valid direct PTR was not accepted: %+v ok=%v", got, ok)
	}
	for name, change := range map[string]func(*normalized.Event){
		"no direct marker": func(e *normalized.Event) { e.Payload["l2_source_mac_direct"] = false },
		"unicast":          func(e *normalized.Event) { e.Flow["dst_ip"] = "10.1.1.24" },
		"other source":     func(e *normalized.Event) { e.Source = "unknown" },
		"other record":     func(e *normalized.Event) { e.Payload["record_type"] = "A" },
		"off scope":        func(e *normalized.Event) { e.Subject["ip"] = "8.8.8.8" },
		"source mismatch":  func(e *normalized.Event) { e.Flow["src_ip"] = "10.1.1.25" },
		"invalid mac":      func(e *normalized.Event) { e.Payload["responder_l2_mac"] = "01:00:00:00:00:24" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := passiveLivePTRTestEvent("ptr-invalid", at, 120)
			change(&candidate)
			if _, ok := passiveLivePTRFact(candidate, scope); ok {
				t.Fatal("untrusted PTR formed a live endpoint hint")
			}
		})
	}
}

func TestPassiveLivePTRLatestEventPreservesWithdrawalAndLateArrival(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	at := time.Now().UTC().Truncate(time.Second)
	positive, _ := passiveLivePTRFact(passiveLivePTRTestEvent("positive", at, 120), scope)
	withdrawn, _ := passiveLivePTRFact(passiveLivePTRTestEvent("withdrawn", at.Add(time.Minute), 0), scope)
	late, _ := passiveLivePTRFact(passiveLivePTRTestEvent("late", at.Add(30*time.Second), 120), scope)
	if !withdrawn.Withdrawn || !withdrawn.ValidUntil.Equal(withdrawn.ObservedAt) {
		t.Fatalf("TTL zero was not a withdrawal: %+v", withdrawn)
	}
	got := passiveLatestLivePTRFacts([]passiveLivePTRFactRow{positive, withdrawn, late})
	if len(got) != 1 || got[0].EventID != "withdrawn" || !got[0].Withdrawn {
		t.Fatalf("late positive resurrected a withdrawn service: %+v", got)
	}
}
