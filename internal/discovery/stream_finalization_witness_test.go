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
		streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt, len(prepared), segment.FileID, segment.StartOffset, segment.EndOffset).
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
