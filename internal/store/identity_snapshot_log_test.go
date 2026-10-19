package store

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
)

// Every committed snapshot leaves one small metadata row: the coverage intervals and the snapshot
// timeline come from this log, so full documents no longer have to be kept to answer them.
func TestSnapshotCommitRecordsMetadataLog(t *testing.T) {
	db, mock := newReconcileMock(t)
	snapshot := adapterSnapshot(t, "s1", "a1", "10.0.0.1")
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT content_sha256 FROM identity_snapshot_log WHERE`).WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
	mock.ExpectExec(`INSERT INTO identity_full_snapshots`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(snapshotLogInsertSQL)).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "snapshot-replay", reconcileObserved, 1800, 1, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM identity_full_snapshots WHERE ctid IN`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM identity_snapshot_log WHERE ctid IN`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_pipeline_scopes\(scope_key`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(snapshotPublishSQL)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if _, err := (&PostgresStore{db: db}).CommitIdentitySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Replay detection reads the log, which outlives the pruned documents: an old snapshot replayed
// after its document was pruned is still recognised and not stored again.
func TestSnapshotReplayIsDetectedFromLog(t *testing.T) {
	db, mock := newReconcileMock(t)
	snapshot := adapterSnapshot(t, "s1", "a1", "10.0.0.1")
	stored, err := (&PostgresStore{db: db}).snapshotDigest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT content_sha256 FROM identity_snapshot_log WHERE`).WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}).AddRow(stored))
	mock.ExpectCommit()
	created, err := (&PostgresStore{db: db}).CommitIdentitySnapshot(context.Background(), snapshot)
	if err != nil || created {
		t.Fatalf("replay created=%t err=%v", created, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Only snapshots whose membership reached the projection may count as coverage; the projection marks
// them, so a snapshot it skipped never claims confirmations it did not apply.
func TestProjectionMarksSnapshotProjected(t *testing.T) {
	db, mock := newReconcileMock(t)
	snapshot := IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: "snap-p", ObservedAt: reconcileObserved, IntervalSeconds: 1800}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`SELECT set_config\('statement_timeout'`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(identityWriteLockSQL)).WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	mock.ExpectQuery(`INSERT INTO account_identity_projection_sources`).WillReturnRows(sqlmock.NewRows([]string{"latest"}).AddRow(true))
	mock.ExpectExec(regexp.QuoteMeta(snapshotLogProjectedSQL)).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "snap-p").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE account_identity_session_projection SET document=jsonb_set`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = projectIdentitySnapshot(context.Background(), tx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Coverage from the log matches the old per-snapshot computation: each snapshot covers three
// intervals, overlapping windows merge, and a source outage leaves a gap.
func TestCoverageFromLogMatchesOldComputation(t *testing.T) {
	base := reconcileObserved
	at := func(m int) time.Time { return base.Add(time.Duration(m) * time.Minute) }
	log := []snapshotMeta{
		{Scope: reconcileScope, SnapshotID: "1", ObservedAt: at(0), IntervalSeconds: 1800},
		{Scope: reconcileScope, SnapshotID: "2", ObservedAt: at(30), IntervalSeconds: 1800},
		{Scope: reconcileScope, SnapshotID: "3", ObservedAt: at(300), IntervalSeconds: 1800},
	}
	var old []IdentitySnapshot
	for _, s := range log {
		old = append(old, IdentitySnapshot{IdentityScope: s.Scope, SnapshotID: s.SnapshotID, ObservedAt: s.ObservedAt, IntervalSeconds: s.IntervalSeconds})
	}
	want := reconcileIdentitySessions([]policy.Session{eventRow("x", "a", "10.0.0.9", at(-1))}, old, at(400))[0].SourceCoverage
	got := coverageFromLog(log, at(400))[reconcileScope]
	if len(got) != 2 || len(want) != 2 || !got[0].From.Equal(want[0].From) || !got[0].To.Equal(want[0].To) || !got[1].From.Equal(want[1].From) || !got[1].To.Equal(want[1].To) {
		t.Fatalf("coverage got=%v want=%v", got, want)
	}
}

func TestSnapshotLogMigrationBackfillsProjectedState(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/postgres/149_identity_snapshot_log.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"CREATE TABLE IF NOT EXISTS identity_snapshot_log", "projected boolean NOT NULL DEFAULT false", "FROM identity_full_snapshots", "account_identity_projection_sources"} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("migration lacks %q", required)
		}
	}
}

// eventRow is a session written from the realtime identity event path, still open.
func eventRow(id, account, ip string, confirmedAt time.Time) policy.Session {
	return policy.Session{
		ID: id, AccountID: account, IP: ip, Source: reconcileScope.Source, SensorID: reconcileScope.SensorID,
		CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain,
		Status: "start", StartedAt: confirmedAt.Add(-time.Minute), ConfirmedAt: confirmedAt,
		Confirmations: []time.Time{confirmedAt}, HeartbeatSeconds: 1800,
	}
}
