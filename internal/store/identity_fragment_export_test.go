package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestIdentityFragmentSegmentKeepsFixedArchiveIdentity(t *testing.T) {
	accepted := time.Date(2026, time.October, 31, 23, 59, 59, 0, time.UTC)
	event := normalized.Event{EventID: "source-position-1", Type: "identity", Timestamp: accepted.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor"}, Subject: map[string]any{"campus_id": "campus"}, Flow: map[string]any{}, Payload: map[string]any{"access_domain": "domain"}}
	parts, err := splitIdentityInboxFragments([]normalized.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(parts[0].JSON, &payload); err == nil {
		t.Fatal("fragment should be an event array")
	}
	fragment := identityExportFragment{BatchID: "batch", Scope: "scope", Source: "identity-http", Epoch: "identity-fresh-1", Month: "202610", Hash: parts[0].SHA256, KeyScheme: "source_position_v1", First: 0, Count: 1, Accepted: accepted, Payload: parts[0].JSON}
	segment, token, err := identityFragmentSegment(fragment)
	if err != nil {
		t.Fatal(err)
	}
	if segment.ArchiveMonth != "202610" || segment.EndOffset != 1 || segment.KeyScheme != "source_position_v1" || segment.NeedsProjection || len(segment.Events) != 1 || token == "" {
		t.Fatalf("unexpected segment: %+v token=%s", segment, token)
	}
	fragment.Accepted = accepted.Add(2 * time.Hour)
	if _, _, err := identityFragmentSegment(fragment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("cross-month retry changed fixed archive month: %v", err)
	}
	fragment.Accepted = accepted
	fragment.Hash = "different"
	if _, _, err := identityFragmentSegment(fragment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("different content at same fragment key was accepted: %v", err)
	}
}

func TestIdentityFragmentSegmentPreservesRepeatedSourcePositions(t *testing.T) {
	accepted := time.Date(2026, time.October, 24, 15, 0, 0, 0, time.UTC)
	event := normalized.Event{EventID: "same-source-record", Type: "identity", Timestamp: accepted.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor"}, Subject: map[string]any{"campus_id": "campus"}, Payload: map[string]any{"access_domain": "domain"}}
	parts, err := splitIdentityInboxFragments([]normalized.Event{event, event})
	if err != nil {
		t.Fatal(err)
	}
	fragment := identityExportFragment{BatchID: "batch", Scope: "scope", Source: "identity-http", Epoch: "identity-fresh-1", Month: "202610", Hash: parts[0].SHA256, KeyScheme: "source_position_v1", First: 50, Count: 2, Accepted: accepted, Payload: parts[0].JSON}
	segment, _, err := identityFragmentSegment(fragment)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareStreamEvents(segment)
	if err != nil || len(prepared) != 2 || prepared[0].key == prepared[1].key {
		t.Fatalf("repeated records must keep distinct fixed positions: %v %+v", err, prepared)
	}
	fragment.KeyScheme = "event_id_v1"
	if _, _, err := identityFragmentSegment(fragment); !errors.Is(err, ErrInvalidIdentityBatch) {
		t.Fatalf("legacy scheme should expose duplicate event IDs: %v", err)
	}
}
