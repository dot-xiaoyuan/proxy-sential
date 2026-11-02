package discovery

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func finalizationWitnessSegment() streamlog.Segment {
	return streamlog.Segment{
		Epoch: "fresh", Source: "passive-discovery", SourcePath: "bond0", FileID: "collector-a",
		StartOffset: 100, EndOffset: 200, ArchiveMonth: "202611", NeedsProjection: true,
		AcceptedAt: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC),
		Events:     []normalized.Event{streamDiscoveryEvent("stream2-fixed", "2026-11-01T10:00:00Z", 600)},
	}
}

func TestProjectionMarkerCarriesSourcePositionForNewSegments(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := finalizationWitnessSegment()
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WithArgs("segment-a", segment.Epoch, segment.Source, segment.SourcePath,
		streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, len(prepared), segment.FileID, segment.StartOffset, segment.EndOffset, "event").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\\$1 FOR UPDATE").WithArgs("segment-a").
		WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(streamProjectionSegmentHash(segment, prepared)))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).projectPreparedStreamSegment(context.Background(), "segment-a", segment, prepared); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSegmentReceiptProjectionBindsOnlyFreshStream2Keys(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Events[0].Timestamp = "invalid-observation-time"
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].HasFact {
		t.Fatalf("expected a receipt without a device fact: %+v %v", prepared, err)
	}
	for _, fresh := range []bool{true, false} {
		t.Run(map[bool]string{true: "fresh", false: "duplicate"}[fresh], func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec("INSERT INTO stream_projection_segments").WithArgs("segment-a", segment.Epoch, segment.Source, segment.SourcePath,
				streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, 1, segment.FileID, segment.StartOffset, segment.EndOffset, "segment").
				WillReturnResult(sqlmock.NewResult(0, 1))
			keys := sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"})
			if fresh {
				keys.AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash)
			}
			mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WillReturnRows(keys)
			if fresh {
				mock.ExpectExec("INSERT INTO stream_discovery_receipts").WithArgs(sqlmock.AnyArg(), segment.Epoch, sqlmock.AnyArg(), "segment", "segment-a").
					WillReturnResult(sqlmock.NewResult(0, 1))
			} else {
				mock.ExpectQuery("JOIN stream_discovery_event_keys_compact k").WillReturnRows(
					sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).
						AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
				mock.ExpectExec("UPDATE stream_projection_segments SET archive_receipt_mode='event'").WithArgs("segment-a").
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec("INSERT INTO stream_discovery_segment_receipt_manifests").WithArgs("segment-a", segment.ArchiveMonth,
					segment.BodyLayout, streamManifestResults{nil}).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			mock.ExpectCommit()
			if err := (StreamDiscoveryProjector{DB: db, CompactOnly: true, SegmentArchiveReceipts: true, ReceiptManifestShadow: !fresh}).
				projectPreparedStreamSegment(context.Background(), "segment-a", segment, prepared); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReceiptManifestShadowCommitsWithReceiptOrRollsBack(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Events[0].Timestamp = "invalid-observation-time"
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].HasFact {
		t.Fatalf("expected a rejected receipt without a fact: %+v %v", prepared, err)
	}
	for _, fail := range []bool{false, true} {
		name := "committed"
		if fail {
			name = "manifest_failure"
		}
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec("INSERT INTO stream_projection_segments").WithArgs("segment-a", segment.Epoch, segment.Source, segment.SourcePath,
				streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, 1, segment.FileID, segment.StartOffset, segment.EndOffset, "segment").
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WithArgs(segment.Epoch, sqlmock.AnyArg(),
				streamArchiveKeys{prepared[0].Receipt}, "segment-a").WillReturnRows(
				sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).
					AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
			mock.ExpectExec("INSERT INTO stream_discovery_receipts").WithArgs(sqlmock.AnyArg(), segment.Epoch, sqlmock.AnyArg(), "segment", "segment-a").
				WillReturnResult(sqlmock.NewResult(0, 1))
			manifest := mock.ExpectExec("INSERT INTO stream_discovery_segment_receipt_manifests").WithArgs("segment-a", segment.ArchiveMonth,
				segment.BodyLayout, streamManifestResults{prepared[0].Receipt.Result})
			if fail {
				manifest.WillReturnError(errors.New("manifest failed"))
				mock.ExpectRollback()
			} else {
				manifest.WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			}
			got := (StreamDiscoveryProjector{DB: db, CompactOnly: true, SegmentArchiveReceipts: true, ReceiptManifestShadow: true}).
				projectPreparedStreamSegment(context.Background(), "segment-a", segment, prepared)
			if (got != nil) != fail {
				t.Fatalf("projection error = %v, want failure=%v", got, fail)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReceiptManifestShadowLeavesReplayedOrdinalEmpty(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Events[0].Timestamp = "invalid-observation-time"
	second := segment.Events[0]
	second.EventID = "stream2-second"
	segment.Events = []normalized.Event{segment.Events[0], {Type: "diagnostic", EventID: "not-projected"}, second}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 2 {
		t.Fatalf("prepare two receipt positions: %v, %+v", err, prepared)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WithArgs("segment-a", segment.Epoch, segment.Source, segment.SourcePath,
		streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, 2, segment.FileID, segment.StartOffset, segment.EndOffset, "segment").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WithArgs(segment.Epoch, sqlmock.AnyArg(),
		streamArchiveKeys{prepared[0].Receipt, prepared[1].Receipt}, "segment-a").WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).
			AddRow(prepared[1].Receipt.Scope, prepared[1].Receipt.Key, prepared[1].Receipt.Hash))
	mock.ExpectQuery("JOIN stream_discovery_event_keys_compact k").WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).
			AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectExec("UPDATE stream_projection_segments SET archive_receipt_mode='event'").WithArgs("segment-a").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_discovery_receipts").WithArgs(sqlmock.AnyArg(), segment.Epoch, sqlmock.AnyArg(), "pending", nil).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_discovery_segment_receipt_manifests").WithArgs("segment-a", segment.ArchiveMonth,
		segment.BodyLayout, streamManifestResults{nil, prepared[1].Receipt.Result}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db, CompactOnly: true, SegmentArchiveReceipts: true, ReceiptManifestShadow: true}).
		projectPreparedStreamSegment(context.Background(), "segment-a", segment, prepared); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestWritesKeepMixedSegmentAndSkipStaticReceipts(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Events[0].Timestamp = "invalid-observation-time"
	second := segment.Events[0]
	second.EventID = "stream2-second"
	segment.Events = []normalized.Event{segment.Events[0], second}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 2 {
		t.Fatalf("prepare: %v, %+v", err, prepared)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WithArgs("segment-a", segment.Epoch, segment.Source, segment.SourcePath,
		streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, 2, segment.FileID, segment.StartOffset, segment.EndOffset, "manifest").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO stream_discovery_event_keys_compact").WithArgs(segment.Epoch, sqlmock.AnyArg(),
		streamArchiveKeys{prepared[0].Receipt, prepared[1].Receipt}, "segment-a").WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).
			AddRow(prepared[1].Receipt.Scope, prepared[1].Receipt.Key, prepared[1].Receipt.Hash))
	mock.ExpectQuery("JOIN stream_discovery_event_keys_compact k").WillReturnRows(
		sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).
			AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectQuery("SELECT .*since").WillReturnRows(sqlmock.NewRows([]string{"since"}))
	mock.ExpectExec("INSERT INTO stream_discovery_segment_receipt_manifests").WithArgs("segment-a", segment.ArchiveMonth,
		segment.BodyLayout, streamManifestResults{nil, prepared[1].Receipt.Result}, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	projector := StreamDiscoveryProjector{DB: db, CompactOnly: true, SegmentArchiveReceipts: true, ReceiptManifestWrites: true}
	if err := projector.projectPreparedStreamSegment(context.Background(), "segment-a", segment, prepared); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestReceiptSplitPreservesRecognitionInput(t *testing.T) {
	items := []streamPreparedDiscovery{
		{Protocol: "arp", Parsed: true, HasFact: true, Fact: streamDiscoveryFact{Protocol: "arp"}},
		{Protocol: "mdns", Parsed: true, HasFact: true, Fact: streamDiscoveryFact{Protocol: "mdns", RecognitionFields: map[string]string{"model": "printer"}}},
	}
	receipts, omitted := splitStreamManifestReceipts(items, true)
	if len(receipts) != 1 || receipts[0].Protocol != "mdns" || len(omitted) != 1 || omitted[0].Protocol != "arp" {
		t.Fatalf("dynamic recognition input lost: receipts=%+v omitted=%+v", receipts, omitted)
	}
	if got := streamRecognitionSummary(omitted)["arp"]; got.Inputs != 1 || got.Parsed != 1 || got.Insufficient != 1 {
		t.Fatalf("static recognition count lost: %+v", got)
	}
	receipts, omitted = splitStreamManifestReceipts(items, false)
	if len(receipts) != 0 || len(omitted) != len(items) || streamRecognitionSummary(omitted)["mdns"].Features != 1 {
		t.Fatalf("pre-cutoff diagnostic gap lost from manifest: receipts=%d omitted=%d", len(receipts), len(omitted))
	}
}

func TestManifestFreshDiagnosticsRejectsBadCutoff(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .*since").WillReturnRows(sqlmock.NewRows([]string{"since"}).AddRow(nil))
	mock.ExpectRollback()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := streamManifestFreshDiagnostics(context.Background(), tx, time.Now().UTC()); err == nil {
		t.Fatal("existing cutoff without since was treated as no cutoff")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamFinalizationWitnessRetriesUnknownOutcome(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := finalizationWitnessSegment()
	args := []driver.Value{"segment-a", segment.Epoch, segment.Source, segment.SourcePath, segment.FileID, segment.StartOffset, segment.EndOffset, 1}
	mock.ExpectExec("UPDATE stream_projection_segments").WithArgs(args...).WillReturnError(errors.New("response lost"))
	projector := StreamDiscoveryProjector{DB: db}
	if err := projector.MarkStreamSegmentFinalized(context.Background(), "segment-a", segment); err == nil {
		t.Fatal("unknown PostgreSQL outcome was accepted without retry")
	}
	mock.ExpectExec("UPDATE stream_projection_segments").WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT epoch,source_kind,source_path").WithArgs("segment-a").WillReturnRows(
		sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "source_file_id", "source_start_offset", "source_end_offset", "event_count", "lanes_finalized_at"}).
			AddRow(segment.Epoch, segment.Source, segment.SourcePath, segment.FileID, segment.StartOffset, segment.EndOffset, 1, time.Now().UTC()))
	if err := projector.MarkStreamSegmentFinalized(context.Background(), "segment-a", segment); err != nil {
		t.Fatalf("committed witness was not recovered: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamFinalizationWitnessWritesOnlyOnce(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := finalizationWitnessSegment()
	mock.ExpectExec("UPDATE stream_projection_segments").WithArgs("segment-a", segment.Epoch, segment.Source, segment.SourcePath,
		segment.FileID, segment.StartOffset, segment.EndOffset, 1).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamSegmentFinalized(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamFinalizationWitnessPreservesLegacyAndRejectsConflict(t *testing.T) {
	segment := finalizationWitnessSegment()
	for _, scenario := range []struct {
		name string
		row  []driver.Value
		want error
	}{
		{"legacy projection", []driver.Value{segment.Epoch, segment.Source, segment.SourcePath, nil, nil, nil, 1, nil}, nil},
		{"different source position", []driver.Value{segment.Epoch, segment.Source, segment.SourcePath, "other-file", segment.StartOffset, segment.EndOffset, 1, time.Now().UTC()}, streamlog.ErrContentConflict},
		{"partial witness", []driver.Value{segment.Epoch, segment.Source, segment.SourcePath, segment.FileID, segment.StartOffset, segment.EndOffset, 1, nil}, streamlog.ErrUnconfirmed},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectExec("UPDATE stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("SELECT epoch,source_kind,source_path").WithArgs("segment-a").WillReturnRows(
				sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "source_file_id", "source_start_offset", "source_end_offset", "event_count", "lanes_finalized_at"}).AddRow(scenario.row...))
			err = (StreamDiscoveryProjector{DB: db}).MarkStreamSegmentFinalized(context.Background(), "segment-a", segment)
			if !errors.Is(err, scenario.want) || scenario.want == nil && err != nil {
				t.Fatalf("unexpected witness result: %v, want %v", err, scenario.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamFinalizationWitnessRequiresProjectedRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec("UPDATE stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT epoch,source_kind,source_path").WillReturnRows(sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "source_file_id", "source_start_offset", "source_end_offset", "event_count", "lanes_finalized_at"}))
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamSegmentFinalized(context.Background(), "segment-a", finalizationWitnessSegment()); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("missing projection was finalized: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
