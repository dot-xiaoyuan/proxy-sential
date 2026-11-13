package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func sidecarNDPEvent(id, at, message, target string, ttl int) normalized.Event {
	return normalized.Event{
		SchemaVersion: "v1", EventID: id, Source: "packet-sidecar", SourceEventType: "ndp", Type: "device", Timestamp: at,
		Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a", "interface": "bond0"},
		Subject:  map[string]any{"campus_id": "site-a", "ip": "fe80::1234", "mac": "02:00:00:00:00:34"},
		Flow:     map[string]any{"src_ip": "fe80::1234", "dst_ip": target, "proto": "ndp"},
		Payload:  map[string]any{"access_domain": "bond0", "origin": "ndp", "message": message, "target": target, "ttl": ttl},
	}
}

func TestSidecarNDPMessageAndTargetAreEvidenceNotStateChanges(t *testing.T) {
	events := []normalized.Event{
		sidecarNDPEvent("ns-1", "2026-11-12T03:57:00Z", "neighbor_solicitation", "fe80::abcd", 600),
		sidecarNDPEvent("na-1", "2026-11-12T03:57:30Z", "neighbor_advertisement", "fe80::1234", 600),
		sidecarNDPEvent("ns-2", "2026-11-12T03:58:00Z", "neighbor_solicitation", "fe80::beef", 600),
	}
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "packet-a", Source: "device-signals", AcceptedAt: time.Date(2026, 11, 12, 3, 58, 1, 0, time.UTC), Events: events})
	if err != nil || len(prepared) != 3 {
		t.Fatalf("prepare NDP replay: %d %v", len(prepared), err)
	}
	for i := 1; i < len(prepared); i++ {
		old, next := prepared[0], prepared[i]
		if !old.HasFact || !next.HasFact || old.Fact.Device != next.Fact.Device || old.Fact.Key != next.Fact.Key || old.Fact.SemanticHash != next.Fact.SemanticHash {
			t.Fatalf("NDP message/target changed state identity or hash: old=%+v next=%+v", old.Fact, next.Fact)
		}
		if decision := mergeStreamDiscoveryFact(&old.Fact, next.Fact); decision.Result != "repeat_observation" || decision.VisibleChanged || !decision.WriteFact || decision.EvidenceEvent != old.Fact.Event {
			t.Fatalf("NDP evidence variation became a state change: %+v", decision)
		}
	}
	if events[0].Payload["message"] != "neighbor_solicitation" || events[0].Payload["target"] != "fe80::abcd" || events[1].Payload["message"] != "neighbor_advertisement" || events[1].Payload["target"] != "fe80::1234" {
		t.Fatal("source evidence was rewritten")
	}
}

func TestSidecarNDPWithdrawalBindingAndLateEventRemainDistinct(t *testing.T) {
	base := sidecarNDPEvent("base", "2026-11-12T03:57:00Z", "neighbor_solicitation", "fe80::abcd", 600)
	withdrawn := sidecarNDPEvent("withdrawn", "2026-11-12T03:57:30Z", "neighbor_advertisement", "fe80::1234", 0)
	bound := sidecarNDPEvent("bound", "2026-11-12T03:57:40Z", "neighbor_advertisement", "fe80::1234", 600)
	bound.Payload["address_binding"] = true
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "packet-a", Source: "device-signals", AcceptedAt: time.Date(2026, 11, 12, 3, 58, 1, 0, time.UTC), Events: []normalized.Event{base, withdrawn, bound}})
	if err != nil || len(prepared) != 3 {
		t.Fatalf("prepare NDP transitions: %d %v", len(prepared), err)
	}
	first, removed, binding := prepared[0].Fact, prepared[1].Fact, prepared[2].Fact
	if decision := mergeStreamDiscoveryFact(&first, binding); decision.Result != "corrected" || !decision.VisibleChanged || !binding.AddressBinding {
		t.Fatalf("explicit address binding change was lost: %+v", decision)
	}
	if decision := mergeStreamDiscoveryFact(&first, removed); decision.Result != "withdrawn" || !decision.VisibleChanged {
		t.Fatalf("withdrawal was lost: %+v", decision)
	}
	if decision := mergeStreamDiscoveryFact(&removed, binding); decision.Result != "restored" || !decision.VisibleChanged || !binding.AddressBinding {
		t.Fatalf("address binding restoration was lost: %+v", decision)
	}
	if first.SemanticHash == binding.SemanticHash {
		t.Fatal("explicit binding did not change semantic hash")
	}
	if decision := mergeStreamDiscoveryFact(&binding, first); decision.Result != "late_history" || decision.WriteFact {
		t.Fatalf("late NDP event displaced current binding: %+v", decision)
	}
	changedMAC := sidecarNDPEvent("different-mac", "2026-11-12T03:57:50Z", "neighbor_solicitation", "fe80::abcd", 600)
	changedMAC.Subject["mac"] = "02:00:00:00:00:35"
	changed, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "packet-a", Source: "device-signals", AcceptedAt: time.Date(2026, 11, 12, 3, 58, 1, 0, time.UTC), Events: []normalized.Event{changedMAC}})
	if err != nil || len(changed) != 1 || changed[0].Fact.SemanticHash == first.SemanticHash {
		t.Fatalf("MAC change was hidden: %+v %v", changed, err)
	}
}
