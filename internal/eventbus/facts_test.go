package eventbus

import (
	"encoding/json"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func discoveryFactEnvelope(t *testing.T) Envelope {
	t.Helper()
	event := normalized.Event{
		SchemaVersion:   "1.0",
		EventID:         "evt-fact-1",
		Source:          "packet-sidecar",
		SourceEventType: "dns_sd",
		Type:            "discovery",
		Timestamp:       "2026-10-30T05:00:00.000000000Z",
		Observer: map[string]any{
			"sensor_id":        "ncu-184-router-pilot",
			"capture_scope_id": "scope-1",
			"source_id":        "passive-1",
			"interface":        "bond0",
		},
		Subject: map[string]any{
			"ip":     "10.202.3.45",
			"mac":    "f2:a3:f8:ec:15:eb",
			"site":   "ncu",
			"domain": "bond0-passive-pilot",
			"vlan":   "992",
		},
		Payload: map[string]any{
			"origin":           "dns_sd",
			"is_response":      true,
			"service_instance": "printer._ipp._tcp.local.",
			"service_type":     "_ipp._tcp",
			"ttl":              120,
		},
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       event.EventID,
		PartitionKey:  "device-1",
		ObservedAt:    time.Date(2026, 10, 30, 5, 0, 0, 0, time.UTC),
		ContentHash:   "sha256:fact",
		Event:         raw,
	}
}

func TestFactFromEnvelope(t *testing.T) {
	fact, err := FactFromEnvelope(discoveryFactEnvelope(t))
	if err != nil {
		t.Fatal(err)
	}
	if fact.DeviceKey == "" || fact.FactKey == "" || fact.EventID != "evt-fact-1" {
		t.Fatalf("unexpected fact identity: %#v", fact)
	}
	if fact.Protocol != "dns_sd" || fact.IP != "10.202.3.45" || fact.SensorID != "ncu-184-router-pilot" {
		t.Fatalf("unexpected fact fields: %#v", fact)
	}
	if fact.ServiceInstance != "printer._ipp._tcp.local." || fact.Version == 0 || len(fact.Observation) == 0 {
		t.Fatalf("unexpected fact payload: %#v", fact)
	}
}

func TestFactFromEnvelopeRejectsInvalidBody(t *testing.T) {
	if _, err := FactFromEnvelope(Envelope{}); err == nil {
		t.Fatal("expected empty body error")
	}
	if _, err := FactFromEnvelope(Envelope{Event: json.RawMessage(`{"type":"identity"}`)}); err == nil {
		t.Fatal("expected non-discovery error")
	}
}
