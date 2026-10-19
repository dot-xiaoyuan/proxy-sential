package store

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
	mock.ExpectQuery(`SELECT content_sha256 FROM identity_snapshot_log`).WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
	mock.ExpectExec(`INSERT INTO identity_full_snapshots`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_snapshot_log`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM identity_full_snapshots WHERE ctid IN`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_pipeline_scopes\(scope_key`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE identity_pipeline_scopes SET snapshot_id=`).WillReturnResult(sqlmock.NewResult(0, 1))
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

// The indexer reads the newest unindexed snapshot of its own sensor inside the retention window,
// one document per pass, and writes members before the index row: the index row fires the
// shared-scope wake trigger, so it must come last. Expired rows are then pruned in bounded batches.
func TestSharedIndexerWritesMembersBeforeIndexRow(t *testing.T) {
	db, mock := newReconcileMock(t)
	event := universityIdentityEvent("ev-idx", "sess-idx", "reconcile", reconcileObserved.Format(time.RFC3339Nano))
	snapshot := IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: "snap-idx", ObservedAt: reconcileObserved, IntervalSeconds: 60, Events: []normalized.Event{event}}
	document, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(regexp.QuoteMeta(sharedIndexSelectSQL)).
		WithArgs(reconcileScope.SensorID, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "snapshot_id", "observed_at", "document"}).
			AddRow(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "snap-idx", reconcileObserved, document))
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO shared_identity_snapshot_members`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO shared_identity_snapshot_indexes`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectSharedPrune(mock)
	indexed, err := (&DBStore{pg: &PostgresStore{db: db, sensorID: reconcileScope.SensorID}}).indexPendingSharedSnapshots(context.Background())
	if err != nil || indexed != 1 {
		t.Fatalf("indexed=%d err=%v", indexed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectSharedPrune(mock sqlmock.Sqlmock) {
	mock.ExpectExec(regexp.QuoteMeta(sharedMembersPruneSQL)).WithArgs(sqlmock.AnyArg(), sharedPruneBatch).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(sharedIndexesPruneSQL)).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
}

// With nothing pending a pass reads no document; it still prunes expired rows.
func TestSharedIndexerIdlePassReadsNoDocumentAndPrunes(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectQuery(regexp.QuoteMeta(sharedIndexSelectSQL)).
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "snapshot_id", "observed_at", "document"}))
	expectSharedPrune(mock)
	indexed, err := (&DBStore{pg: &PostgresStore{db: db, sensorID: reconcileScope.SensorID}}).indexPendingSharedSnapshots(context.Background())
	if err != nil || indexed != 0 {
		t.Fatalf("indexed=%d err=%v", indexed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Historical snapshots are never indexed: only the newest one inside the retention window, of this
// process's sensor. Two materializer processes used to index the same 490-snapshot backlog.
func TestSharedIndexerSelectsNewestOwnSnapshotOnly(t *testing.T) {
	for _, required := range []string{"f.sensor_id=$1", "f.observed_at>$2", "ORDER BY f.observed_at DESC", "LIMIT 1"} {
		if !strings.Contains(sharedIndexSelectSQL, required) {
			t.Fatalf("selection lacks %q: %s", required, sharedIndexSelectSQL)
		}
	}
	if !strings.Contains(sharedMembersPruneSQL, "ORDER BY received_at LIMIT $2") {
		t.Fatalf("member prune not bounded and index-ordered: %s", sharedMembersPruneSQL)
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
