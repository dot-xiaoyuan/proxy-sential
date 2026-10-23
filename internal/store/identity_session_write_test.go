package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSessionBatchPublishesMetadataWithOneWrite(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	// Metadata must be present in the same INSERT/ON CONFLICT operation; a
	// separate UPDATE rewrites every index and fires downstream triggers twice.
	mock.ExpectExec(`(?s)INSERT INTO account_sessions\(.*session_status, policy_metadata\).*ON CONFLICT\(session_id\) DO UPDATE SET`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = upsertAccountSessionsBatch(context.Background(), tx, []AccountSession{{SessionID: "session", AccountID: "account", StartedAt: "2026-10-23T06:00:00Z", LastConfirmedAt: "2026-10-23T06:01:00Z"}}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBatchDoesNotGrowIntoRepeatedTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name            string
		size, processed int
		elapsed         time.Duration
		want            int
	}{
		{"slow full batch shrinks", 800, 800, 25 * time.Second, 400},
		{"moderate full batch holds", 400, 400, 15 * time.Second, 400},
		{"fast full batch grows", 100, 100, 2 * time.Second, 200},
		{"partial batch holds", 200, 42, 2 * time.Second, 200},
		{"minimum is retained", 50, 50, 25 * time.Second, 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextIdentityTimedBatchSize(tc.size, nil, tc.processed, tc.elapsed); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestIdentityLookupIndexSurvivesMigrationHistory(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/postgres/167_identity_scope_ip_lookup.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, key := range []string{"policy_identity_scope_ip_time_v2", "session_data->>'source'", "session_data->>'sensor_id'", "session_data->>'campus_id'", "session_data->>'access_domain'", "session_data->>'ip'", "observed_at,event_id", "indisvalid", "indisready"} {
		if !strings.Contains(text, key) {
			t.Fatalf("missing required lookup/index validation: %s", key)
		}
	}
}
