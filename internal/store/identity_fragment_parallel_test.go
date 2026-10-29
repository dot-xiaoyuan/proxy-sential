package store

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
)

func TestIdentityFragmentCompatibilityDoesNotRewriteAuthorityOrTakeGlobalLock(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('statement_timeout'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO account_sessions.*ON CONFLICT`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO shared_device_profile_jobs`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	tx, _ := db.Begin()
	events := []normalized.Event{{Type: "identity", EventID: "login", Source: "ncu-srun4k", Timestamp: "2026-10-29T04:00:00Z", Subject: map[string]any{"entity_role": "endpoint", "endpoint_id": "mac:02:00:00:00:00:01", "account_id": "account-a", "ip": "192.0.2.1", "mac": "02:00:00:00:00:01"}, Payload: map[string]any{"session_id": "session-a", "action": "login"}}}
	if err = writeIdentityFragmentCompatibilityTx(context.Background(), tx, events); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityFragmentSessionsRetainNewestStateAndOldStart(t *testing.T) {
	login := normalized.Event{Type: "identity", EventID: "login", Source: "ncu-srun4k", Timestamp: "2026-10-29T04:00:00Z", Subject: map[string]any{"entity_role": "endpoint", "endpoint_id": "mac:02:00:00:00:00:01", "account_id": "account-a", "ip": "192.0.2.1"}, Payload: map[string]any{"session_id": "session-a", "action": "login"}}
	logout := login
	logout.EventID = "logout"
	logout.Timestamp = "2026-10-29T04:01:00Z"
	logout.Payload = map[string]any{"session_id": "session-a", "action": "logout"}
	for _, events := range [][]normalized.Event{{login, logout}, {logout, login}, {logout, login, logout}} {
		got := fragmentCompatibilitySessions(events)
		if len(got) != 1 || got[0].SessionStatus != "logout" || got[0].StartedAt != login.Timestamp || got[0].EndedAt != logout.Timestamp {
			t.Fatalf("unexpected folded session: %+v", got)
		}
	}
	logout.Timestamp = login.Timestamp
	if got := fragmentCompatibilitySessions([]normalized.Event{logout, login}); len(got) != 1 || got[0].SessionStatus != "logout" {
		t.Fatalf("equal-time login reopened session: %+v", got)
	}
	if !strings.Contains(fragmentSessionUpsertSQL, "session_status = CASE WHEN "+fragmentSessionNewerSQL) || !strings.Contains(fragmentSessionUpsertSQL, "ended_at = GREATEST") {
		t.Fatal("fragment merge lost its out-of-order SQL guards")
	}
}

func TestIdentityDerivedWorkerCountIsBoundedAndOptIn(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
	}{{"", 1}, {"bad", 1}, {"0", 1}, {"-1", 1}, {"2", 2}, {"4", 4}, {"6", 6}, {"100", 6}} {
		t.Setenv("PROXY_SENTINEL_IDENTITY_DERIVED_WORKERS", tc.value)
		if got := identityDerivedWorkerCount(); got != tc.want {
			t.Fatalf("%q: got %d want %d", tc.value, got, tc.want)
		}
	}
}
