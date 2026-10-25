package discovery

import (
	"errors"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func streamDiscoveryEvent(id, at string, ttl int) normalized.Event {
	return normalized.Event{
		SchemaVersion: "v1", EventID: id, Source: "passive", SourceEventType: "dns_sd", Type: "discovery", Timestamp: at,
		Observer: map[string]any{"sensor_id": "sensor-a", "source_id": "passive-a", "capture_scope_id": "scope-a"},
		Subject:  map[string]any{"site": "site-a", "domain": "domain-a", "ip": "10.2.3.4"},
		Payload:  map[string]any{"origin": "dns_sd", "service_type": "_ipp._tcp", "service_instance": "printer-a", "is_response": true, "ttl": ttl, "txt": "ty=HP LaserJet Pro"},
	}
}

func TestPrepareStreamDiscoveryKeepsBothReceiptsAndOneFactForRepeat(t *testing.T) {
	events := []normalized.Event{
		streamDiscoveryEvent("stream-one", "2026-10-24T10:00:00Z", 600),
		streamDiscoveryEvent("stream-two", "2026-10-24T10:00:02Z", 600),
	}
	segment := streamlog.Segment{Epoch: "fresh-1", Source: "dns-sd", Events: events, AcceptedAt: time.Date(2026, 10, 24, 10, 0, 3, 0, time.UTC)}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 2 {
		t.Fatalf("prepare repeated observations: %+v %v", prepared, err)
	}
	if prepared[0].Receipt.Key == prepared[1].Receipt.Key || prepared[0].Fact.Device != prepared[1].Fact.Device || prepared[0].Fact.Key != prepared[1].Fact.Key || prepared[0].Fact.SemanticHash != prepared[1].Fact.SemanticHash {
		t.Fatalf("repeated observations lost distinct receipts or shared fact: %+v", prepared)
	}
	decision := mergeStreamDiscoveryFact(&prepared[0].Fact, prepared[1].Fact)
	if decision.Result != "repeat_observation" || decision.VisibleChanged || !decision.WriteFact {
		t.Fatalf("same fact caused a full visible change: %+v", decision)
	}
	if decision.EvidenceEvent != prepared[0].Fact.Event {
		t.Fatalf("first visible evidence reference missing: %+v", prepared[0].Fact)
	}
	prepared[1].Fact.EvidenceEvent = decision.EvidenceEvent
	at := time.Date(2026, 10, 24, 10, 0, 3, 0, time.UTC)
	firstState, err := buildStreamDiscoveryState("fresh-1", prepared[0].Fact.Device, []streamDiscoveryFact{prepared[0].Fact}, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	secondState, err := buildStreamDiscoveryState("fresh-1", prepared[1].Fact.Device, []streamDiscoveryFact{prepared[1].Fact}, &firstState, at)
	if err != nil {
		t.Fatal(err)
	}
	firstEvidence := streamClassificationEvidence(firstState.Document)
	secondEvidence := streamClassificationEvidence(secondState.Document)
	if len(firstEvidence) != 1 || len(secondEvidence) != 1 || firstEvidence[0] != secondEvidence[0] {
		t.Fatalf("repeat changed visible evidence: %v -> %v", firstEvidence, secondEvidence)
	}
}

func TestStreamDiscoveryFactHandlesLateCorrectionAndWithdrawal(t *testing.T) {
	base := streamDiscoveryEvent("base", "2026-10-24T10:00:00Z", 600)
	newer := streamDiscoveryEvent("newer", "2026-10-24T10:00:10Z", 600)
	withdrawn := streamDiscoveryEvent("withdrawn", "2026-10-24T10:00:11Z", 0)
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "fresh", Source: "dns-sd", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{base, newer, withdrawn}})
	if err != nil {
		t.Fatal(err)
	}
	if decision := mergeStreamDiscoveryFact(&prepared[1].Fact, prepared[0].Fact); decision.Result != "late_history" || decision.WriteFact {
		t.Fatalf("late fact overwrote current: %+v", decision)
	}
	if decision := mergeStreamDiscoveryFact(&prepared[1].Fact, prepared[2].Fact); decision.Result != "withdrawn" || !decision.VisibleChanged {
		t.Fatalf("newer withdrawal did not retract: %+v", decision)
	}
	corrected := newer
	corrected.EventID = "newer-correction"
	corrected.Timestamp = "2026-10-24T10:00:12Z"
	corrected.Payload["txt"] = "ty=HP Color LaserJet"
	more, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "fresh", Source: "dns-sd", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{corrected}})
	if err != nil {
		t.Fatal(err)
	}
	if decision := mergeStreamDiscoveryFact(&prepared[1].Fact, more[0].Fact); decision.Result != "corrected" || !decision.VisibleChanged {
		t.Fatalf("content correction disappeared: %+v", decision)
	}
}

func TestPrepareStreamDiscoveryRejectsSameKeyDifferentContent(t *testing.T) {
	one := streamDiscoveryEvent("same", "2026-10-24T10:00:00Z", 600)
	two := streamDiscoveryEvent("same", "2026-10-24T10:00:00Z", 600)
	two.Payload["txt"] = "ty=other"
	_, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "fresh", Source: "dns-sd", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{one, two}})
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("same position content conflict was accepted: %v", err)
	}
}

func TestPrepareStreamDiscoverySkipsUnselectedSignalsInMixedSegment(t *testing.T) {
	selected := streamDiscoveryEvent("selected", "2026-10-25T09:00:00Z", 600)
	selected.Type = "device"
	selected.SourceEventType = "ssdp"
	selected.Payload["is_response"] = true
	unselected := streamDiscoveryEvent("coverage", "2026-10-25T09:00:01Z", 600)
	unselected.Type = "device"
	unselected.SourceEventType = "capture_coverage"
	segment := streamlog.Segment{Epoch: "fresh", Source: "device-signals", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{selected, unselected}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].Receipt.Key != "fresh:selected" {
		t.Fatalf("mixed segment must project only selected discovery evidence: %+v %v", prepared, err)
	}
}

func TestPrepareStreamDiscoveryProjectsSidecarSSDPAnnouncement(t *testing.T) {
	event := normalized.Event{SchemaVersion: "v1", EventID: "ssdp-one", Source: "packet-sidecar", SourceEventType: "ssdp", Type: "device", Timestamp: "2026-10-25T10:00:00Z",
		Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a", "interface": "bond0"},
		Subject:  map[string]any{"campus_id": "site-a", "ip": "10.2.3.4"},
		Payload:  map[string]any{"access_domain": "bond0", "nt": "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "usn": "uuid:router::urn:schemas-upnp-org:device:InternetGatewayDevice:1"}}
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "fresh", Source: "device-signals", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{event}})
	if err != nil || len(prepared) != 1 || !prepared[0].HasFact || prepared[0].Receipt.Result != "applied" || prepared[0].Fact.Protocol != "ssdp" || prepared[0].Fact.DeviceType != "gateway" {
		t.Fatalf("sidecar SSDP announcement lost: %+v %v", prepared, err)
	}
}

func TestPrepareStreamDiscoveryProjectsIEEE1905ClientAndWithdrawal(t *testing.T) {
	base := normalized.Event{SchemaVersion: "v1", EventID: "assoc-one", Source: "packet-sidecar", SourceEventType: "ieee1905_client_association", Type: "device", Timestamp: "2026-10-25T10:00:00Z",
		Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a", "interface": "bond0"},
		Subject:  map[string]any{"campus_id": "site-a", "mac": "f4:fc:49:75:16:f6"},
		Payload:  map[string]any{"access_domain": "bond0", "client_mac": "60:7e:a4:78:95:f3", "association_state": "joined", "bssid": "f4:fc:49:75:16:f6"}}
	left := base
	left.EventID = "assoc-two"
	left.Timestamp = "2026-10-25T10:00:01Z"
	left.Payload = map[string]any{"access_domain": "bond0", "client_mac": "60:7e:a4:78:95:f3", "association_state": "left", "bssid": "f4:fc:49:75:16:f6"}
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "fresh", Source: "device-signals", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{base, left}})
	if err != nil || len(prepared) != 2 || !prepared[0].HasFact || !prepared[1].HasFact || prepared[0].Fact.MAC != "60:7e:a4:78:95:f3" || prepared[0].Fact.Device != prepared[1].Fact.Device || !prepared[1].Fact.Withdrawn {
		t.Fatalf("IEEE1905 client association semantics lost: %+v %v", prepared, err)
	}
}
