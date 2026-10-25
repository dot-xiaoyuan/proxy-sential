package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/fingerprint"
)

func TestStreamRouterCursorClaimsBySensorAndRejectsLostLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &DBStore{pg: &PostgresStore{db: db}}
	stamp := time.Date(2026, 10, 25, 8, 30, 0, 0, time.UTC)
	mock.ExpectQuery(`UPDATE stream_router_recognition_state SET`).WithArgs("sensor-a", "owner-a", fingerprint.DefaultRouterRuleSet().Version).
		WillReturnRows(sqlmock.NewRows([]string{"cursor_indexed_at", "cursor_event_key"}).AddRow(stamp, "fresh:event-1"))
	cursor, claimed, err := store.claimStreamRouterRecognition(context.Background(), "sensor-a", "owner-a")
	if err != nil || !claimed || !cursor.IndexedAt.Equal(stamp) || cursor.EventKey != "fresh:event-1" {
		t.Fatalf("incorrect source claim: %+v claimed=%t err=%v", cursor, claimed, err)
	}
	mock.ExpectExec(`UPDATE stream_router_recognition_state SET`).WithArgs("sensor-a", "owner-a", stamp, true, "fresh:event-1", 1, "").
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.finishStreamRouterRecognition(context.Background(), "sensor-a", cursor, 1, nil); !errors.Is(err, errRecognitionLeaseLost) {
		t.Fatalf("lost lease advanced the stream cursor: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRouterCursorWaitsForAuditedCutover(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &DBStore{pg: &PostgresStore{db: db}}
	mock.ExpectQuery(`UPDATE stream_router_recognition_state SET`).WithArgs("sensor-a", "owner-a", fingerprint.DefaultRouterRuleSet().Version).
		WillReturnRows(sqlmock.NewRows([]string{"cursor_indexed_at", "cursor_event_key"}))
	mock.ExpectQuery(`SELECT rule_version FROM stream_router_recognition_state`).WithArgs("sensor-a").
		WillReturnRows(sqlmock.NewRows([]string{"rule_version"}))
	if _, claimed, err := store.claimStreamRouterRecognition(context.Background(), "sensor-a", "owner-a"); err != nil || claimed {
		t.Fatalf("router history was claimed without an audited fresh cutover: claimed=%t err=%v", claimed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRouterCursorStopsBeforeIndexRetentionGap(t *testing.T) {
	store := &DBStore{}
	cursor := streamRouterCursor{IndexedAt: time.Now().UTC().Add(-8 * 24 * time.Hour), EventKey: "old:event", Owner: "owner-a"}
	if _, _, err := store.streamRouterSignalBatch(context.Background(), "sensor-a", cursor); !errors.Is(err, ErrStreamRouterIndexGap) {
		t.Fatalf("expired index cursor skipped old source gap: %v", err)
	}
}
