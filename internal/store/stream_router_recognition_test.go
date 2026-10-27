package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/fingerprint"
)

func TestRouterScoreInputMigrationKeepsIndexAvailableDuringReplacement(t *testing.T) {
	body, err := os.ReadFile("../../migrations/clickhouse/056_stream_router_score_input.sql")
	if err != nil {
		t.Fatal(err)
	}
	statements, err := splitClickHouseMigration(string(body))
	if err != nil || len(statements) != 3 {
		t.Fatalf("invalid router migration: statements=%d err=%v", len(statements), err)
	}
	if !strings.Contains(statements[0], "ADD COLUMN IF NOT EXISTS router_score_possible") ||
		!strings.Contains(statements[1], "CREATE MATERIALIZED VIEW IF NOT EXISTS stream_router_signal_index_mv_v2") ||
		!strings.Contains(statements[1], "WHERE router_score_possible=1") ||
		!strings.Contains(statements[2], "DROP VIEW IF EXISTS stream_router_signal_index_mv") {
		t.Fatalf("router index replacement can create a write gap: %v", statements)
	}
}

func TestRouterWeakBatchesCoalesceWithoutScoring(t *testing.T) {
	start := streamRouterCursor{IndexedAt: time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC), EventKey: "start"}
	reads, scores := 0, 0
	read := func(_ context.Context, cursor streamRouterCursor) ([]normalized.Event, streamRouterCursor, error) {
		reads++
		if reads > 5 {
			t.Fatal("weak batch exceeded bounded claim")
		}
		return []normalized.Event{{Type: "device", Source: "packet-sidecar", SourceEventType: "ttl", Subject: map[string]any{"ip": "192.0.2.1"}, Payload: map[string]any{"ttl": 64}}}, streamRouterCursor{IndexedAt: start.IndexedAt.Add(time.Duration(reads) * time.Second), EventKey: "next"}, nil
	}
	next, count, weak, _, _, err := runStreamRouterClaimBatches(context.Background(), start, read, func(context.Context, []normalized.Event) error { scores++; return nil })
	if err != nil || reads != 5 || scores != 0 || count != 5 || weak != 5 || !next.IndexedAt.Equal(start.IndexedAt.Add(5*time.Second)) {
		t.Fatalf("coalesced claim next=%+v count=%d weak=%d reads=%d scores=%d err=%v", next, count, weak, reads, scores, err)
	}
}

func TestRouterWeakBatchReadFailureKeepsDurableCursor(t *testing.T) {
	start := streamRouterCursor{IndexedAt: time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC), EventKey: "start"}
	reads := 0
	read := func(_ context.Context, cursor streamRouterCursor) ([]normalized.Event, streamRouterCursor, error) {
		reads++
		if reads == 2 {
			return nil, cursor, errors.New("body read failed")
		}
		return []normalized.Event{{Type: "device", Source: "packet-sidecar", SourceEventType: "ttl", Subject: map[string]any{"ip": "192.0.2.1"}, Payload: map[string]any{"ttl": 64}}}, streamRouterCursor{IndexedAt: start.IndexedAt.Add(time.Second), EventKey: "first"}, nil
	}
	next, count, _, _, _, err := runStreamRouterClaimBatches(context.Background(), start, read, func(context.Context, []normalized.Event) error { t.Fatal("weak event scored"); return nil })
	if err == nil || count != 0 || next != start {
		t.Fatalf("failed claim advanced cursor: next=%+v count=%d err=%v", next, count, err)
	}
}

func TestRouterWeakThenScoredBatchCommitsTogetherOnlyAfterScoring(t *testing.T) {
	start := streamRouterCursor{IndexedAt: time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC), EventKey: "start"}
	reads, scores := 0, 0
	read := func(_ context.Context, cursor streamRouterCursor) ([]normalized.Event, streamRouterCursor, error) {
		reads++
		if reads > 2 {
			t.Fatal("read after scored batch")
		}
		event := normalized.Event{Type: "device", Source: "packet-sidecar", SourceEventType: "ttl", Subject: map[string]any{"ip": "192.0.2.1"}, Payload: map[string]any{"ttl": 64}}
		if reads == 2 {
			event = normalized.Event{Type: "router", Source: "zeek", SourceEventType: "lldp", Subject: map[string]any{"ip": "192.0.2.2"}, Payload: map[string]any{"capabilities": "Router"}}
		}
		return []normalized.Event{event}, streamRouterCursor{IndexedAt: start.IndexedAt.Add(time.Duration(reads) * time.Second), EventKey: "next"}, nil
	}
	next, count, weak, _, _, err := runStreamRouterClaimBatches(context.Background(), start, read, func(_ context.Context, events []normalized.Event) error {
		scores++
		if reads != 2 || len(events) != 1 || events[0].SourceEventType != "lldp" {
			t.Fatalf("scored wrong batch: reads=%d events=%+v", reads, events)
		}
		return nil
	})
	if err != nil || reads != 2 || scores != 1 || count != 2 || weak != 1 || !next.IndexedAt.Equal(start.IndexedAt.Add(2*time.Second)) {
		t.Fatalf("mixed claim next=%+v count=%d weak=%d reads=%d scores=%d err=%v", next, count, weak, reads, scores, err)
	}
	reads = 0
	next, count, _, _, _, err = runStreamRouterClaimBatches(context.Background(), start, read, func(context.Context, []normalized.Event) error { return errors.New("scoring failed") })
	if err == nil || count != 0 || next != start {
		t.Fatalf("failed scoring advanced cursor: next=%+v count=%d err=%v", next, count, err)
	}
}

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
