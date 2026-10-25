package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
)

func TestFreshPolicyReadUsesOnlyPositionFactsAfterCutover(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_POLICY_FRESH_ONLY", "true")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	fact := policy.Session{ID: "session-1", AccountID: "account-1", Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth", ConfirmedAt: at.Add(-time.Second)}
	raw, _ := json.Marshal(fact)
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM stream_source_cutovers`).WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	mock.ExpectQuery(`SELECT session_data FROM identity_stream_policy_facts WHERE`).WithArgs(sqlmock.AnyArg(), at).WillReturnRows(sqlmock.NewRows([]string{"session_data"}).AddRow(raw))
	sessions, err := (&PostgresStore{db: db}).ListPolicySessions(context.Background(), at)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != "session-1" {
		t.Fatalf("fresh policy fact missing: %+v", sessions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFreshPolicyReadRejectsMissingCutover(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_POLICY_FRESH_ONLY", "true")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM stream_source_cutovers`).WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(false))
	if _, err := (&PostgresStore{db: db}).ListPolicySessions(context.Background(), time.Now()); err == nil {
		t.Fatal("fresh read silently proceeded without a source cutover")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
