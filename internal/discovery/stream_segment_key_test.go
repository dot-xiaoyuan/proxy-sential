package discovery

import (
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestParsePassiveStream3KeyRequiresCanonicalLocator(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, epoch, key string
		valid            bool
		ordinal          int
	}{
		{"first", "fresh-1", "fresh-1:stream3-" + id + "-0", true, 0},
		{"last", "fresh-1", "fresh-1:stream3-" + id + "-1999", true, 1999},
		{"wrong_epoch", "fresh-2", "fresh-1:stream3-" + id + "-0", false, 0},
		{"old_scheme", "fresh-1", "fresh-1:stream2-" + id + "-0", false, 0},
		{"upper_hex", "fresh-1", "fresh-1:stream3-" + strings.Repeat("A", 64) + "-0", false, 0},
		{"short_id", "fresh-1", "fresh-1:stream3-" + id[:63] + "-0", false, 0},
		{"non_hex", "fresh-1", "fresh-1:stream3-" + strings.Repeat("g", 64) + "-0", false, 0},
		{"leading_zero", "fresh-1", "fresh-1:stream3-" + id + "-00", false, 0},
		{"overflow", "fresh-1", "fresh-1:stream3-" + id + "-2000", false, 0},
		{"negative", "fresh-1", "fresh-1:stream3-" + id + "--1", false, 0},
		{"suffix", "fresh-1", "fresh-1:stream3-" + id + "-1x", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotOrdinal, ok := ParsePassiveStream3Key(tc.epoch, tc.key)
			if ok != tc.valid || ok && (gotID != id || gotOrdinal != tc.ordinal) {
				t.Fatalf("parse: id=%q ordinal=%d valid=%v", gotID, gotOrdinal, ok)
			}
		})
	}
}

func stream3ProjectionTestSegment() (string, streamlog.Segment) {
	segment := streamlog.Segment{Epoch: "fresh-1", Source: "passive-discovery", SourcePath: "packet://test",
		FileID: "capture-a", StartOffset: 0, EndOffset: 100, ArchiveMonth: "202611",
		AcceptedAt: time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC), NeedsProjection: true,
		Events: []normalized.Event{streamDiscoveryEvent("placeholder", "2026-11-03T00:00:00Z", 600)}}
	id := streamlog.SourceSegmentID(segment)
	segment.Events[0].EventID = "stream3-" + id + "-0"
	return id, segment
}

func TestStream3ProjectionRequiresSourceBoundOrdinalAndScope(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || !isSegmentKeyedPassiveSegment(segment) || verifyStream3PreparedSegment(id, segment, prepared) != nil {
		t.Fatalf("valid source-bound segment rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*streamlog.Segment)
	}{
		{"wrong_ordinal", func(s *streamlog.Segment) { s.Events[0].EventID = "stream3-" + id + "-1" }},
		{"wrong_source_position", func(s *streamlog.Segment) { s.EndOffset++ }},
		{"wrong_month", func(s *streamlog.Segment) { s.ArchiveMonth = "202612" }},
		{"mixed_scope", func(s *streamlog.Segment) {
			second := streamDiscoveryEvent("stream3-"+id+"-1", "2026-11-03T00:00:01Z", 600)
			second.Observer["capture_scope_id"] = "other-scope"
			s.Events = append(s.Events, second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := segment
			copy.Events = append([]normalized.Event(nil), segment.Events...)
			tc.change(&copy)
			items, err := prepareStreamDiscovery(copy)
			if err == nil && verifyStream3PreparedSegment(id, copy, items) == nil {
				t.Fatal("conflicting stream3 source admitted")
			}
		})
	}
}
