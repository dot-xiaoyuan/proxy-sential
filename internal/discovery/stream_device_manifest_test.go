package discovery

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

func TestDeviceSignalManifestArchiveConfirmationUsesLegacyLocator(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Source = "device-signals"
	segment.SourcePath = "/signals/device.jsonl"
	segment.RawIsStandardEvents = true
	segment.Events[0].EventID = "stream-old-stable-key"
	id := streamlog.SourceSegmentID(segment)
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT archive_receipt_mode,epoch,source_kind").WithArgs(id).WillReturnRows(
		sqlmock.NewRows([]string{"archive_receipt_mode", "epoch", "source_kind", "source_path", "content_sha256", "source_file_id", "source_start_offset", "source_end_offset", "event_count"}).
			AddRow("manifest", segment.Epoch, segment.Source, segment.SourcePath, streamProjectionSegmentHash(segment, prepared), segment.FileID, segment.StartOffset, segment.EndOffset, len(prepared)))
	mock.ExpectQuery("FROM stream_discovery_segment_receipt_manifests m").
		WithArgs(id, segment.Epoch, sqlmock.AnyArg(), streamAcceptedMonth(segment.AcceptedAt), int64(0)).
		WillReturnRows(sqlmock.NewRows([]string{"archive_month", "body_layout", "results", "matched"}).
			AddRow(segment.ArchiveMonth, segment.BodyLayout, len(prepared), len(prepared)))
	if err := (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), id, segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceSignalLegacyManifestReceiptRequiresFinalizedProof(t *testing.T) {
	for _, finalized := range []bool{false, true} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		key := "fresh-1:stream-old-stable-key"
		accepted := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
		id := streamlog.SourceSegmentID(streamlog.Segment{Epoch: "fresh-1", Source: "device-signals", SourcePath: "/signals/device.jsonl", FileID: "file-a", StartOffset: 0, EndOffset: 100})
		mock.ExpectQuery("stream_discovery_event_keys k").WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}))
		var witness any
		if finalized {
			witness = accepted.Add(time.Second)
		}
		mock.ExpectQuery("stream_discovery_segment_receipt_manifests m").WillReturnRows(sqlmock.NewRows(deviceManifestReceiptColumns).
			AddRow(key, strings.Repeat("a", 64), accepted, accepted, id, 0, "fresh-1", "device-signals", "/signals/device.jsonl", "manifest", 1, accepted, accepted, witness, "file-a", int64(0), int64(100), int64(0), "202611", "", "device-signals", 1, "applied"))
		got, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
		if err != nil || !found {
			t.Fatalf("finalized=%v receipt=%v found=%v err=%v", finalized, got, found, err)
		}
		want := "pending"
		if finalized {
			want = "confirmed"
		}
		if got["archive_state"] != want {
			t.Fatalf("state %v, want %s", got["archive_state"], want)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}

func TestDeviceSignalManifestRejectsMissingLocator(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := "fresh-1:stream-stable"
	mock.ExpectQuery("stream_discovery_event_keys k").WillReturnRows(sqlmock.NewRows([]string{"content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}))
	missing := make([]driver.Value, len(deviceManifestReceiptColumns))
	missing[0], missing[1], missing[2], missing[3] = key, "abc", time.Now(), time.Now()
	mock.ExpectQuery("stream_discovery_segment_receipt_manifests m").WillReturnRows(sqlmock.NewRows(deviceManifestReceiptColumns).AddRow(missing...))
	_, _, err = (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "fresh-1", "scope-a", key)
	if !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("missing locator accepted: %v", err)
	}
}

func TestDeviceSignalProjectionWritesLegacyKeyAndManifestWithoutEventReceipt(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Source = "device-signals"
	segment.SourcePath = "/signals/device.jsonl"
	segment.RawIsStandardEvents = true
	segment.Events[0].EventID = "stream-old-stable-key"
	segment.Events[0].Timestamp = "invalid-observation-time"
	id := streamlog.SourceSegmentID(segment)
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil || len(prepared) != 1 || prepared[0].HasFact {
		t.Fatalf("rejected fixture: %+v %v", prepared, err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("(?s)INSERT INTO stream_projection_segments.*passive_key_scheme,source_generation").
		WithArgs(id, segment.Epoch, segment.Source, segment.SourcePath, streamProjectionSegmentHash(segment, prepared), segment.AcceptedAt,
			1, segment.FileID, segment.StartOffset, segment.EndOffset, "manifest", int64(0)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("(?s)INSERT INTO stream_discovery_event_keys.*receipt_segment_id,receipt_ordinal").
		WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).
			AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectExec("(?s)INSERT INTO stream_discovery_segment_receipt_manifests.*device-signals").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db, DeviceSignalManifestWrites: true}).ProjectStreamSegment(context.Background(), id, segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceSignalCommittedManifestRecoversWithWriterSwitchOff(t *testing.T) {
	segment := finalizationWitnessSegment()
	segment.Source = "device-signals"
	segment.SourcePath = "/signals/device.jsonl"
	segment.RawIsStandardEvents = true
	segment.Events[0].EventID = "stream-old-stable-key"
	id := streamlog.SourceSegmentID(segment)
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT content_sha256 FROM stream_projection_segments").WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(streamProjectionSegmentHash(segment, prepared)))
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), id, segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
