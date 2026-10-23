package store

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"testing"
	"time"
)

func TestIdentityIntervalArchiveFailurePreservesOnlyCopy(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "failed", false: "verified"}[fail], func(t *testing.T) {
			db, m := newReconcileMock(t)
			fake := &fakeArchive{fail: fail}
			received := reconcileObserved.Add(-31 * 24 * time.Hour)
			m.ExpectQuery(`FROM identity_projection_intervals p WHERE p.first_received_at`).WillReturnRows(sqlmock.NewRows([]string{"scope", "session", "ip", "hash", "received", "confirmed", "document"}).AddRow(IdentityScopeKey(reconcileScope), "s", "192.0.2.1", "digest", received, received.Add(-time.Hour), []byte(`{"session_id":"s","account_id":"a","ended_at":"2026-01-01T00:00:00Z"}`)))
			if !fail {
				m.ExpectExec(`DELETE FROM identity_projection_intervals p USING`).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			n, err := (&DBStore{pg: &PostgresStore{db: db}, ch: fake.serve(t)}).archiveIdentityIntervalBatch(context.Background(), reconcileObserved)
			if fail && (err == nil || n != 0) {
				t.Fatalf("failed archive deleted data n=%d err=%v", n, err)
			}
			if !fail && (err != nil || n != 1 || fake.rows[0]["first_received_at"] == nil) {
				t.Fatalf("verified archive n=%d err=%v rows=%v", n, err, fake.rows)
			}
			if err := m.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
