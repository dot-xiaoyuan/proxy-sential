package eventbus

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestNewDiscoveryEnvelope(t *testing.T) {
	at := time.Date(2026, 10, 30, 2, 15, 0, 123, time.UTC)
	event := testEvent("stream-event-a", at)
	segment := testSegment(at.Add(2*time.Second), event)
	envelope, err := NewDiscoveryEnvelope("segment-a", segment, event, "device-key-a")
	if err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != SchemaVersion || envelope.EventID != event.EventID || envelope.PartitionKey != "device-key-a" {
		t.Fatalf("envelope = %+v", envelope)
	}
	if envelope.SensorID != "sensor-a" || envelope.ScopeID != "scope-a" {
		t.Fatalf("source fields = %+v", envelope)
	}
	if !envelope.ObservedAt.Equal(at) || !envelope.AcceptedAt.Equal(segment.AcceptedAt) {
		t.Fatalf("times = %s %s", envelope.ObservedAt, envelope.AcceptedAt)
	}
	if !strings.HasPrefix(envelope.ContentHash, "sha256:") || len(envelope.ContentHash) != len("sha256:")+64 {
		t.Fatalf("content hash = %q", envelope.ContentHash)
	}
	var decoded map[string]any
	if err := json.Unmarshal(envelope.Event, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["event_id"] != event.EventID {
		t.Fatalf("event payload = %+v", decoded)
	}
	raw, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Envelope
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.ContentHash != envelope.ContentHash || string(roundTrip.Key()) != string(envelope.Key()) {
		t.Fatalf("round trip = %+v", roundTrip)
	}
}

func TestNewDiscoveryEnvelopeRejectsIncompleteInput(t *testing.T) {
	at := time.Now().UTC()
	event := testEvent("event-a", at)
	segment := testSegment(at, event)
	for _, tc := range []struct {
		name      string
		segmentID string
		segment   streamlog.Segment
		event     normalized.Event
		key       string
	}{
		{name: "missing segment", segmentID: "", segment: segment, event: event, key: "key"},
		{name: "missing key", segmentID: "segment", segment: segment, event: event, key: ""},
		{name: "missing event id", segmentID: "segment", segment: segment, event: withEventID(event, ""), key: "key"},
		{name: "missing accepted", segmentID: "segment", segment: withAccepted(segment, time.Time{}), event: event, key: "key"},
		{name: "bad time", segmentID: "segment", segment: segment, event: withTimestamp(event, "not-a-time"), key: "key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDiscoveryEnvelope(tc.segmentID, tc.segment, tc.event, tc.key); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func withEventID(event normalized.Event, id string) normalized.Event {
	event.EventID = id
	return event
}

func withTimestamp(event normalized.Event, timestamp string) normalized.Event {
	event.Timestamp = timestamp
	return event
}

func withAccepted(segment streamlog.Segment, at time.Time) streamlog.Segment {
	segment.AcceptedAt = at
	return segment
}
