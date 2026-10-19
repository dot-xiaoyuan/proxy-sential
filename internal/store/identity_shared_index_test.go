package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
)

// A commit must not write shared-observation members inline: that work held the snapshot
// transaction open for a 38k-member snapshot while the identity database was saturated.
func TestSnapshotCommitDoesNotIndexSharedMembersInline(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_SHARED_OBSERVATION_ENABLED", "true")
	db, mock := newReconcileMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT content_sha256 FROM identity_full_snapshots`).WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
	mock.ExpectQuery(`SELECT max\(observed_at\) FROM identity_full_snapshots`).WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(nil))
	mock.ExpectQuery(`FROM account_sessions WHERE ended_at IS NULL AND source = \$1`).WillReturnRows(sqlmock.NewRows(sessionRowColumns()))
	mock.ExpectExec(`INSERT INTO identity_full_snapshots`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	snapshot := snapshotWith()
	created, err := (&PostgresStore{db: db}).CommitIdentitySnapshot(context.Background(), snapshot)
	if err != nil || !created {
		t.Fatalf("commit created=%t err=%v", created, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The indexer reads committed snapshots without an index row and writes members before the index
// row: the index row fires the shared-scope wake trigger, so it must come last.
func TestSharedIndexerWritesMembersBeforeIndexRow(t *testing.T) {
	db, mock := newReconcileMock(t)
	event := universityIdentityEvent("ev-idx", "sess-idx", "reconcile", reconcileObserved.Format(time.RFC3339Nano))
	snapshot := IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: "snap-idx", ObservedAt: reconcileObserved, IntervalSeconds: 60, Events: []normalized.Event{event}}
	document, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`FROM identity_full_snapshots f WHERE NOT EXISTS`).
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "snapshot_id", "observed_at", "document"}).
			AddRow(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "snap-idx", reconcileObserved, document))
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO shared_identity_snapshot_members`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO shared_identity_snapshot_indexes`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	indexed, err := (&DBStore{pg: &PostgresStore{db: db}}).indexPendingSharedSnapshots(context.Background())
	if err != nil || indexed != 1 {
		t.Fatalf("indexed=%d err=%v", indexed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// With nothing pending the pass issues only the selection and reports zero.
func TestSharedIndexerIdlePassIssuesOnlySelection(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectQuery(`FROM identity_full_snapshots f WHERE NOT EXISTS`).
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "snapshot_id", "observed_at", "document"}))
	indexed, err := (&DBStore{pg: &PostgresStore{db: db}}).indexPendingSharedSnapshots(context.Background())
	if err != nil || indexed != 0 {
		t.Fatalf("indexed=%d err=%v", indexed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Members are written in bounded chunks, and the index row is still the last statement.
func TestSharedIndexChunksMembersThenIndexes(t *testing.T) {
	db, mock := newReconcileMock(t)
	snapshot := IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: "snap-big", ObservedAt: reconcileObserved, IntervalSeconds: 60}
	for i := 0; i < 2500; i++ {
		snapshot.Sessions = append(snapshot.Sessions, snapshotMember(fmt.Sprintf("sess-%04d", i), "acct-big", "10.1.0.1"))
	}
	mock.ExpectBegin()
	for range []int{1000, 1000, 500} {
		mock.ExpectExec(`INSERT INTO shared_identity_snapshot_members`).WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectExec(`INSERT INTO shared_identity_snapshot_indexes`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := indexSharedSnapshot(context.Background(), db, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
