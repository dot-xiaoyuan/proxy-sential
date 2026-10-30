package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestStreamPartitionKeyPrefersDeviceAndStaysStable(t *testing.T) {
	at := time.Date(2026, 10, 30, 2, 15, 0, 0, time.UTC).Format(time.RFC3339Nano)
	first := streamDiscoveryEvent("event-a", at, 600)
	second := streamDiscoveryEvent("event-b", at, 600)
	firstKey, firstSource := StreamPartitionKey(first)
	secondKey, secondSource := StreamPartitionKey(second)
	if firstSource != "device" || secondSource != "device" {
		t.Fatalf("sources = %q %q", firstSource, secondSource)
	}
	if firstKey == "" || firstKey != secondKey {
		t.Fatalf("device key is not stable: %q %q", firstKey, secondKey)
	}
}

func TestStreamPartitionKeyFallsBackToScopedMACIPAndEvent(t *testing.T) {
	at := time.Date(2026, 10, 30, 2, 15, 0, 0, time.UTC).Format(time.RFC3339Nano)
	observer := map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a"}
	base := normalized.Event{
		SchemaVersion:   "v1",
		Source:          "test",
		SourceEventType: "unknown-protocol",
		Type:            "discovery",
		Timestamp:       at,
		Observer:        observer,
		Subject:         map[string]any{"site": "site-a", "domain": "domain-a"},
		Payload:         map[string]any{},
	}
	macEvent := base
	macEvent.EventID = "event-mac"
	macEvent.Subject = map[string]any{"site": "site-a", "domain": "domain-a", "mac": "02:00:00:00:00:10"}
	macKey, macSource := StreamPartitionKey(macEvent)
	if macSource != "mac" || macKey == "" {
		t.Fatalf("mac fallback = %q %q", macKey, macSource)
	}
	if again, _ := StreamPartitionKey(macEvent); again != macKey {
		t.Fatalf("mac key unstable: %q %q", macKey, again)
	}

	ipEvent := base
	ipEvent.EventID = "event-ip"
	ipEvent.Subject = map[string]any{"site": "site-a", "domain": "domain-a", "ip": "198.51.100.10"}
	ipKey, ipSource := StreamPartitionKey(ipEvent)
	if ipSource != "ip" || ipKey == "" || ipKey == macKey {
		t.Fatalf("ip fallback = %q %q", ipKey, ipSource)
	}

	eventOnly := base
	eventOnly.EventID = "event-only"
	eventKey, eventSource := StreamPartitionKey(eventOnly)
	if eventSource != "event" || eventKey == "" {
		t.Fatalf("event fallback = %q %q", eventKey, eventSource)
	}

	empty := base
	empty.EventID = ""
	if key, source := StreamPartitionKey(empty); key != "" || source != "" {
		t.Fatalf("empty event key = %q %q", key, source)
	}
}
