package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

func TestExtractDiscoveryHandshakeCluesKeepsOnlyRecentMatchingIPAndEvidence(t *testing.T) {
	now := time.Date(2026, 11, 1, 3, 20, 0, 0, time.UTC)
	makeRow := func(ip, eventID string, samples ...sharedaccess.HandshakeSample) sharedObservationEvent {
		payload, _ := json.Marshal(map[string]any{"handshake_schema": "handshake-samples/v1", "feature_samples": samples})
		return sharedObservationEvent{IP: ip, EventID: eventID, Payload: string(payload)}
	}
	rows := []sharedObservationEvent{
		makeRow("192.0.2.1", "event-a", sharedaccess.HandshakeSample{Family: "user_agent", Value: "Mozilla/5.0 (Windows NT 10.0)", EventID: "packet-a", ObservedAt: now.Add(-5 * time.Minute), DestinationPort: 80}, sharedaccess.HandshakeSample{Family: "ja3", Value: strings.Repeat("A", 32), EventID: "packet-b", ObservedAt: now.Add(-4 * time.Minute), DestinationPort: 443}, sharedaccess.HandshakeSample{Family: "ja4", Value: "t13d1516h2_8daaf6152771_e5627efa2ab1", EventID: "packet-h", ObservedAt: now.Add(-3 * time.Minute), DestinationPort: 443}),
		makeRow("192.0.2.2", "other-ip", sharedaccess.HandshakeSample{Family: "user_agent", Value: "Android", EventID: "packet-c", ObservedAt: now.Add(-time.Minute)}),
		makeRow("192.0.2.1", "event-b", sharedaccess.HandshakeSample{Family: "user_agent", Value: "Mozilla/5.0 (Windows NT 10.0)", EventID: "packet-d", ObservedAt: now.Add(-2 * time.Minute)}, sharedaccess.HandshakeSample{Family: "ja4", Value: "not captured", EventID: "packet-e", ObservedAt: now.Add(-time.Minute)}, sharedaccess.HandshakeSample{Family: "ja3", Value: "invalid", EventID: "packet-f", ObservedAt: now.Add(-time.Minute)}),
		makeRow("192.0.2.1", "old", sharedaccess.HandshakeSample{Family: "user_agent", Value: "stale", EventID: "packet-g", ObservedAt: now.Add(-20 * time.Minute)}),
	}
	clues, err := extractDiscoveryHandshakeClues(rows, "192.0.2.1", now.Add(-11*time.Minute), now)
	if err != nil || len(clues) != 3 {
		t.Fatalf("clues=%+v err=%v", clues, err)
	}
	if clues[0].Kind != "user_agent" || clues[0].EvidenceID != "event-b" || clues[0].DestinationPort != 0 || clues[1].Kind != "ja4" || clues[1].EvidenceID != "event-a" || clues[1].DestinationPort != 443 || clues[2].Kind != "ja3" || clues[2].Value != strings.Repeat("a", 32) || clues[2].DestinationPort != 443 {
		t.Fatalf("wrong attribution or deduplication: %+v", clues)
	}
}
