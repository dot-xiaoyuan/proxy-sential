package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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

func TestStream3ProjectionSkipsCompactLedgerAndRollsBackFailedManifest(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[fail], func(t *testing.T) {
			id, segment := stream3ProjectionTestSegment()
			segment.Events[0].Subject["ip"] = "203.0.113.4"
			prepared, err := prepareStreamDiscovery(segment)
			if err != nil || len(prepared) != 1 || prepared[0].HasFact || prepared[0].Receipt.Result != "outside_private_scope" {
				t.Fatalf("test input did not select manifest-only receipt: %+v err=%v", prepared, err)
			}
			scope, hashes, err := stream3ScopeAndHashes(prepared)
			if err != nil {
				t.Fatal(err)
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec("INSERT INTO stream_projection_segments").WithArgs(id, segment.Epoch, segment.Source, segment.SourcePath,
				streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, 1, segment.FileID, segment.StartOffset,
				segment.EndOffset, "manifest", int64(0)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery("SELECT .*since").WillReturnRows(sqlmock.NewRows([]string{"since"}))
			manifest := mock.ExpectExec("INSERT INTO stream_discovery_segment_receipt_manifests").WithArgs(id, segment.ArchiveMonth,
				segment.BodyLayout, streamManifestResults{"outside_private_scope"}, sqlmock.AnyArg(), scope, hashes)
			if fail {
				manifest.WillReturnError(errors.New("manifest write interrupted"))
				mock.ExpectRollback()
			} else {
				manifest.WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			}
			err = (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), id, segment)
			if (err != nil) != fail {
				t.Fatalf("manifest failure=%v projection err=%v", fail, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStream3ProjectionRetryUsesCommittedSegmentMarker(t *testing.T) {
	id, segment := stream3ProjectionTestSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, prior string
		wantErr     bool
	}{
		{"same segment", streamProjectionSegmentHash(segment, prepared), false},
		{"different body", "different-hash", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("SELECT content_sha256,passive_key_scheme,source_generation").WithArgs(id).
				WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "passive_key_scheme", "source_generation"}).AddRow(tc.prior, "stream3", int64(0)))
			if tc.wantErr {
				mock.ExpectRollback()
			} else {
				mock.ExpectCommit()
			}
			err = (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), id, segment)
			if (err != nil) != tc.wantErr {
				t.Fatalf("existing segment hash=%s err=%v", tc.prior, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
