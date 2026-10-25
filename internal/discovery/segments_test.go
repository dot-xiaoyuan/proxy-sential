package discovery

import (
	"fmt"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestDiscoverySegmentsBoundRowsBytesAndOffsets(t *testing.T) {
	events := make([]normalized.Event, 121)
	for i := range events {
		events[i] = normalized.Event{EventID: fmt.Sprintf("event-%03d", i), Payload: map[string]any{"value": strings.Repeat("x", 12000)}}
	}
	segments, err := EncodeDiscoverySegments(events)
	if err != nil {
		t.Fatal(err)
	}
	if len(segments) < 3 {
		t.Fatalf("expected bounded segments, got %d", len(segments))
	}
	offset := 0
	for _, segment := range segments {
		if segment.StartOffset != offset || segment.EventCount < 1 || segment.EventCount > 50 || len(segment.Events) > DiscoverySegmentMaxBytes {
			t.Fatalf("invalid segment at %d: %+v", offset, segment)
		}
		var decoded []normalized.Event
		if err := decodeDiscoveryBatch(segment.Events, &decoded); err != nil || len(decoded) != segment.EventCount || decoded[0].EventID != events[offset].EventID {
			t.Fatalf("segment roundtrip at %d: %v", offset, err)
		}
		offset += segment.EventCount
	}
	if offset != len(events) {
		t.Fatalf("lost events: %d", offset)
	}
}

func TestDiscoverySegmentsRejectUnboundedSingleEvent(t *testing.T) {
	_, err := EncodeDiscoverySegments([]normalized.Event{{EventID: "oversize", Payload: map[string]any{"value": strings.Repeat("x", DiscoveryEventMaxBytes)}}})
	if err == nil {
		t.Fatal("oversize event accepted")
	}
}
