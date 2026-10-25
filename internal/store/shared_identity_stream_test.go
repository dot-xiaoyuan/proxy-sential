package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSharedIdentityFreshFactsUsePositionStore(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_POLICY_FRESH_ONLY", "true")
	db, mock := newReconcileMock(t)
	from := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Minute)
	m := sharedMapping()
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM stream_source_cutovers`).WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	mock.ExpectQuery(`SELECT session_data FROM identity_stream_policy_facts`).
		WithArgs(IdentityScopeKey(reconcileScope), "10.157.2.191", from, to).
		WillReturnRows(sqlmock.NewRows([]string{"session_data"}))
	rows, err := (&PostgresStore{db: db}).querySharedIdentityFacts(context.Background(), m, "10.157.2.191", from, to)
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedIdentityCompatibilityReadsBothFactStores(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_POLICY_FRESH_ONLY", "false")
	db, mock := newReconcileMock(t)
	from := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Minute)
	m := sharedMapping()
	mock.ExpectQuery(`UNION ALL SELECT observed_at,event_id,session_data FROM identity_stream_policy_facts`).
		WithArgs(m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, "10.157.2.191", from, to, IdentityScopeKey(reconcileScope)).
		WillReturnRows(sqlmock.NewRows([]string{"session_data"}))
	rows, err := (&PostgresStore{db: db}).querySharedIdentityFacts(context.Background(), m, "10.157.2.191", from, to)
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
