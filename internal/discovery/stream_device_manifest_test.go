package discovery

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
	"proxy-sentinel/internal/streamlog"
)

func TestDeviceSignalManifestFallbackWithoutPG247PreservesMissingReceipt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		columns    int
		function   bool
		wantAbsent bool
	}{
		{"migration absent", 0, false, true},
		{"partial columns", 1, false, false},
		{"partial function", 0, true, false},
		{"installed schema other missing column", 2, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("SELECT k.event_key,k.content_sha256").WillReturnError(&pgconn.PgError{Code: "42703"})
			mock.ExpectQuery("FROM pg_attribute").WillReturnRows(
				sqlmock.NewRows([]string{"locator_columns", "evidence_function"}).AddRow(tc.columns, tc.function))
			got, err := (Repository{DB: db}).streamDeviceManifestReceipts(context.Background(), "epoch", "scope", []string{"epoch:stream-key"})
			if tc.wantAbsent {
				if err != nil || len(got) != 0 {
					t.Fatalf("missing PG247 should fall through to old receipt semantics: %v %v", got, err)
				}
			} else {
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "42703" {
					t.Fatalf("partial or inconsistent schema was hidden: %v", err)
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyStreamReceiptWithoutPG247StillReportsUnconfirmedKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := "epoch:stream-key"
	mock.ExpectQuery("FROM stream_discovery_event_keys k").WillReturnRows(
		sqlmock.NewRows([]string{"content_sha256", "first_accepted_at", "projected_at", "result", "archive_state", "body_ref"}))
	mock.ExpectQuery("SELECT k.event_key,k.content_sha256").WillReturnError(&pgconn.PgError{Code: "42703"})
	mock.ExpectQuery("FROM pg_attribute").WillReturnRows(
		sqlmock.NewRows([]string{"locator_columns", "evidence_function"}).AddRow(0, false))
	mock.ExpectQuery("SELECT k.event_key FROM jsonb_array_elements_text").WillReturnRows(
		sqlmock.NewRows([]string{"event_key"}).AddRow(key))
	_, found, err := (Repository{DB: db}).StreamDiscoveryReceipt(context.Background(), "epoch", "scope", key)
	if found || !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("old missing-receipt result changed: found=%t err=%v", found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

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
