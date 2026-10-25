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
