package discovery

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type streamJSONFields map[string]string

type streamArchiveKeys []streamDiscoveryReceipt

func (want streamArchiveKeys) Match(v driver.Value) bool {
	raw, ok := v.([]byte)
	if !ok {
		if value, isString := v.(string); isString {
			raw, ok = []byte(value), true
		}
	}
	if !ok {
		return false
	}
	var rows []struct {
		Ordinal int    `json:"ordinal"`
		Scope   string `json:"scope_id"`
		Key     string `json:"event_key"`
		Hash    string `json:"content_sha256"`
	}
	if json.Unmarshal(raw, &rows) != nil || len(rows) != len(want) {
		return false
	}
	for i, row := range rows {
		if row.Ordinal != i || row.Scope != want[i].Scope || row.Key != want[i].Key || row.Hash != want[i].Hash {
			return false
		}
	}
	return true
}

func (want streamJSONFields) Match(v driver.Value) bool {
	raw, ok := v.(string)
	if !ok {
		if b, isBytes := v.([]byte); isBytes {
			raw, ok = string(b), true
		}
	}
	if !ok {
		return false
	}
	var rows []map[string]any
	if json.Unmarshal([]byte(raw), &rows) != nil || len(rows) != 1 {
		return false
	}
	for key, value := range want {
		var actual any = rows[0]
		for _, part := range strings.Split(key, ".") {
			object, ok := actual.(map[string]any)
			if !ok {
				return false
			}
			actual = object[part]
		}
		if actual != value {
			return false
		}
	}
	return true
}

func TestStreamDiscoveryCrossMonthRetryUsesGlobalEventKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", SourcePath: "/log/dns.log", ArchiveMonth: "202611", AcceptedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Events: []normalized.Event{event}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM stream_discovery_event_keys r").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "november-retry", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryConflictingRetryRollsBack(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM stream_discovery_event_keys r").WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow("scope-a", "fresh:fixed-position", "different-content"))
	mock.ExpectRollback()
	err = (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), "november-conflict", segment)
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("content conflict was not isolated: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamDiscoveryReceiptCarriesStableBodyLocator(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := streamDiscoveryEvent("event-a", "2026-10-24T10:00:00Z", 600)
	segment := streamlog.Segment{Epoch: "fresh", ArchiveMonth: "202610", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{event}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_discovery_event_keys").WithArgs("fresh", sqlmock.AnyArg(), streamJSONFields{"event_key": "fresh:event-a", "scope_id": "scope-a"}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO stream_discovery_receipts").WithArgs(sqlmock.AnyArg(), "fresh", streamJSONFields{"event_key": "fresh:event-a", "scope_id": "scope-a", "body_ref.class": "evidence", "body_ref.month": "202610", "body_ref.scope": "scope-a", "body_ref.key": "fresh:event-a", "body_ref.sha256": items[0].Receipt.Hash}).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = writeStreamDiscoveryReceipts(context.Background(), tx, streamAcceptedMonth(segment.AcceptedAt), segment, items); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestExpireStreamDiscoveryStatesUsesBoundedDueKeys(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery("FROM stream_discovery_device_state WHERE expires_at<=now\\(\\)").WithArgs(100).WillReturnRows(sqlmock.NewRows([]string{"epoch", "device_key"}))
	mock.ExpectCommit()
	count, err := (StreamDiscoveryProjector{DB: db}).ExpireStreamDiscoveryStates(context.Background(), 100)
	if err != nil || count != 0 {
		t.Fatalf("empty due set: %d %v", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamArchiveConfirmationUsesOriginalMonthAndAtomicReceiptChecks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		matched bool
	}{
		{"cross_month_and_idempotent", true},
		{"missing_or_conflicting_receipt_rolls_back", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			segment := streamlog.Segment{Epoch: "fresh", ArchiveMonth: "202611", AcceptedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Events: []normalized.Event{
				streamDiscoveryEvent("first", "2026-10-24T10:00:00Z", 600),
				streamDiscoveryEvent("second", "2026-10-24T10:00:00Z", 600),
			}}
			items, err := prepareStreamDiscovery(segment)
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectBegin()
			matched := 2
			if !tc.matched {
				matched = 1
			}
			mock.ExpectQuery(`WITH input AS MATERIALIZED.*jsonb_to_recordset.*ORDER BY v\.ordinal.*FOR UPDATE.*UPDATE stream_discovery_receipts.*SELECT count\(\*\) FROM receipt`).
				WithArgs(segment.Epoch, streamArchiveKeys{items[0].Receipt, items[1].Receipt}).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(matched))
			if tc.matched {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
			err = (StreamDiscoveryProjector{DB: db}).MarkStreamArchiveConfirmed(context.Background(), "november-retry", segment)
			if tc.matched && err != nil {
				t.Fatal(err)
			}
			if !tc.matched && !errors.Is(err, streamlog.ErrUnconfirmed) {
				t.Fatalf("missing receipt accepted: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReconcileStreamProjectionReadsCommittedMarkerWithoutRewriting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", SourcePath: "/log/dns.log", ArchiveMonth: "202611", AcceptedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	digest := contentHash(struct {
		Epoch, Source, Path, File, RawSHA string
		Start, End                        int64
		Events                            []streamDiscoveryReceipt
	}{segment.Epoch, segment.Source, segment.SourcePath, segment.FileID, segment.RawSHA256, segment.StartOffset, segment.EndOffset, streamReceiptList(prepared)})
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(digest))
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionDetectsConflictingCommittedMarker(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow("other"))
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("expected content conflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionMissingMarkerRetriesProjection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM stream_discovery_event_keys r").WithArgs("fresh", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"scope_id", "event_key", "content_sha256"}).AddRow(prepared[0].Receipt.Scope, prepared[0].Receipt.Key, prepared[0].Receipt.Hash))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionMissingMarkerRacesCommittedWriter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		t.Fatal(err)
	}
	digest := streamProjectionSegmentHash(segment, prepared)
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1 FOR UPDATE`).WithArgs("segment-a").WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(digest))
	mock.ExpectCommit()
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileStreamProjectionReadFailureDoesNotAssumeMissing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	segment := streamlog.Segment{Epoch: "fresh", Source: "dns-sd", ArchiveMonth: "202611", AcceptedAt: time.Now().UTC(), Events: []normalized.Event{streamDiscoveryEvent("fixed-position", "2026-10-24T10:00:00Z", 600)}}
	readErr := errors.New("database unavailable")
	mock.ExpectQuery(`SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=\$1`).WithArgs("segment-a").WillReturnError(readErr)
	if err := (StreamDiscoveryProjector{DB: db}).ReconcileStreamProjection(context.Background(), "segment-a", segment); !errors.Is(err, readErr) {
		t.Fatalf("expected read failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
