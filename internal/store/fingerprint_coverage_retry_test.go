package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestFingerprintCoverageRetryBackoffAndRecovery(t *testing.T) {
	delay := time.Duration(0)
	for _, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		delay = nextFingerprintCoverageDelay(delay, false)
		if delay != want {
			t.Fatalf("failure delay=%s, want %s", delay, want)
		}
	}
	if got := nextFingerprintCoverageDelay(delay, true); got != time.Minute {
		t.Fatalf("successful refresh must restore normal schedule, got %s", got)
	}
}

func TestFingerprintFreshCoverageKeepsOldCountsButMarksThemStale(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fresh, err := json.Marshal(map[string]any{"status": "ready", "as_of": time.Now().Add(-4 * time.Minute).UTC().Format(time.RFC3339Nano), "items": []any{map[string]any{"protocol": "dns-sd", "inputs": 42}}})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`name='fingerprint-source-coverage'`).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`name='fingerprint-rebuild'`).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`name='fingerprint-match-counts'`).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow([]byte(`{}`)))
	mock.ExpectQuery(`name='recognition-fresh-coverage'`).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow(fresh))
	result, err := (&DBStore{pg: &PostgresStore{db: db}}).FingerprintSourceCoverage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state, ok := result["fresh"].(map[string]any)
	if !ok || state["status"] != "stale" {
		t.Fatalf("old snapshot presented as current: %#v", result["fresh"])
	}
	items, ok := state["items"].([]any)
	if !ok || len(items) != 1 || items[0].(map[string]any)["inputs"] != float64(42) {
		t.Fatalf("stale snapshot counts were lost: %#v", state["items"])
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
