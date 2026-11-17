package store

import (
	"context"
	"github.com/DATA-DOG/go-sqlmock"
	"regexp"
	"testing"
)

func TestEnsureIdentityProgressSkipsCompleteScope(t *testing.T) {
	db, m := newReconcileMock(t)
	m.ExpectBegin()
	m.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM identity_receive_progress`).WithArgs("scope").
		WillReturnRows(sqlmock.NewRows([]string{"receive", "consume", "export"}).AddRow(true, true, true))
	m.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityProgress(context.Background(), tx, "scope"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureIdentityProgressRepairsPartialScope(t *testing.T) {
	db, m := newReconcileMock(t)
	m.ExpectBegin()
	m.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM identity_receive_progress`).WithArgs("scope").
		WillReturnRows(sqlmock.NewRows([]string{"receive", "consume", "export"}).AddRow(true, false, true))
	for _, table := range []string{"identity_receive_progress", "identity_consume_progress", "identity_export_progress"} {
		m.ExpectExec(`INSERT INTO ` + table).WithArgs("scope").WillReturnResult(sqlmock.NewResult(0, 0))
	}
	m.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityProgress(context.Background(), tx, "scope"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSplitInboxApplyFencesAndCommitsResponsibility(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "true")
	db, m := newReconcileMock(t)
	snapshot := adapterSnapshot(t, "s1", "a1", "10.0.0.1")
	w := identityInboxWork{Scope: IdentityScopeKey(reconcileScope), Generation: "initial", Epoch: 7, Sequence: 1, Events: snapshot.Events, Batches: []identityInboxBatch{{BatchID: "b", Sequence: 1, Count: len(snapshot.Events)}}}
	m.ExpectBegin()
	m.ExpectQuery(`SELECT COALESCE.*FROM identity_consume_progress`).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(true))
	m.ExpectExec(`INSERT INTO policy_identity_observations`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(`INSERT INTO identity_applied_events`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`UPDATE identity_ingest_batches`).WillReturnRows(sqlmock.NewRows([]string{"sequence", "completed"}).AddRow(1, true))
	m.ExpectExec(`DELETE FROM identity_inbox_ip_pending`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(`SELECT scope_key FROM identity_consume_progress.*FOR UPDATE`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(regexp.QuoteMeta(applyIdentitySplitSQL)).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	if err := (&PostgresStore{db: db}).applyIdentityInbox(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSplitInboxExpiredLeaseDoesNotWrite(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_IDENTITY_SPLIT_PROGRESS", "true")
	db, m := newReconcileMock(t)
	m.ExpectBegin()
	m.ExpectQuery(`SELECT COALESCE.*FROM identity_consume_progress`).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(false))
	m.ExpectRollback()
	if err := (&PostgresStore{db: db}).applyIdentityInbox(context.Background(), identityInboxWork{}); err != ErrIdentityLeaseExpired {
		t.Fatalf("got %v", err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
