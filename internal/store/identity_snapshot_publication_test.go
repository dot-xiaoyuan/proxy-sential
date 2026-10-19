package store

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	identityadapter "proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
)

// Counts come straight from the snapshot: dual-stack addresses are one session, and several
// sessions of one account are one account.
func TestSnapshotPublicationCountsDistinctSessionsAndAccounts(t *testing.T) {
	sessions := []policy.Session{
		snapshotMember("s1", "a1", "10.0.0.1"),
		snapshotMember("s1", "a1", "2001:db8::1"),
		snapshotMember("s2", "a1", "10.0.0.2"),
		snapshotMember("s3", "a2", "10.0.0.3"),
	}
	accounts, count, conflict := snapshotPublication(sessions)
	if accounts != 2 || count != 3 || conflict {
		t.Fatalf("accounts=%d sessions=%d conflict=%t want 2 3 false", accounts, count, conflict)
	}
}

// One session owned by two accounts is a conflict; it must never be published as current state.
func TestSnapshotPublicationDetectsSessionOwnedByTwoAccounts(t *testing.T) {
	sessions := []policy.Session{snapshotMember("s1", "a1", "10.0.0.1"), snapshotMember("s1", "a2", "2001:db8::1")}
	if _, _, conflict := snapshotPublication(sessions); !conflict {
		t.Fatal("conflicting ownership not detected")
	}
}

// Publication only moves forward and never touches the generation or the inbox lease: a newer
// publication must not fence in-flight applies.
func TestSnapshotPublishStatementMovesForwardOnly(t *testing.T) {
	if !strings.Contains(snapshotPublishSQL, "snapshot_at IS NULL OR snapshot_at<$2") {
		t.Fatalf("publication not forward-only: %s", snapshotPublishSQL)
	}
	for _, forbidden := range []string{"current_generation", "lease_epoch", "lease_until"} {
		if strings.Contains(snapshotPublishSQL, forbidden) || strings.Contains(snapshotPublishFailedSQL, forbidden) {
			t.Fatalf("publication writes %s", forbidden)
		}
	}
	if !strings.Contains(snapshotPublishFailedSQL, "calibration_state='failed'") || strings.Contains(snapshotPublishFailedSQL, "snapshot_id=") {
		t.Fatalf("conflict must record failure and keep the published snapshot: %s", snapshotPublishFailedSQL)
	}
}

func expectSnapshotCommitPrefix(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT content_sha256 FROM identity_snapshot_log`).WillReturnRows(sqlmock.NewRows([]string{"content_sha256"}))
}

// The commit publishes in the same transaction, with the scope-row write last so its lock is held
// only until commit. Old snapshots of the scope are pruned in bounded steps.
func TestSnapshotCommitPublishesInSameTransaction(t *testing.T) {
	db, mock := newReconcileMock(t)
	expectSnapshotCommitPrefix(mock)
	mock.ExpectExec(`INSERT INTO identity_full_snapshots`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_snapshot_log`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM identity_full_snapshots WHERE ctid IN`)).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, reconcileObserved, snapshotPruneBatch).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(snapshotLogPruneSQL)).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, reconcileObserved.Add(-snapshotMetadataRetention), snapshotPruneBatch).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_pipeline_scopes\(scope_key,source,sensor_id,campus_id,access_domain\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(snapshotPublishSQL)).
		WithArgs(IdentityScopeKey(reconcileScope), reconcileObserved, "snapshot-replay", 1, 1).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	created, err := (&PostgresStore{db: db}).CommitIdentitySnapshot(context.Background(), adapterSnapshot(t, "s1", "a1", "10.0.0.1"))
	if err != nil || !created {
		t.Fatalf("created=%t err=%v", created, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A conflicting snapshot is stored as evidence, but it neither reconciles sessions nor replaces the
// published snapshot; the failure is visible in the scope state.
func TestConflictingSnapshotKeepsPublishedVersionAndSkipsReconcile(t *testing.T) {
	db, mock := newReconcileMock(t)
	expectSnapshotCommitPrefix(mock)
	mock.ExpectExec(`INSERT INTO identity_full_snapshots`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_snapshot_log`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM identity_full_snapshots WHERE ctid IN`)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM identity_snapshot_log WHERE ctid IN`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_pipeline_scopes\(scope_key,source,sensor_id,campus_id,access_domain\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(snapshotPublishFailedSQL)).
		WithArgs(IdentityScopeKey(reconcileScope), reconcileObserved, "session_account_conflict").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	snapshot := adapterSnapshot(t, "s1", "a1", "10.0.0.1")
	other := adapterSnapshot(t, "s1", "a2", "2001:db8::1")
	snapshot.Events = append(snapshot.Events, other.Events...)
	if _, err := (&PostgresStore{db: db}).CommitIdentitySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// adapterSnapshot builds a valid complete-snapshot member through the real identity adapter.
func adapterSnapshot(t *testing.T, sessionID, account, ip string) IdentitySnapshot {
	t.Helper()
	interval := 1800
	var input, output bytes.Buffer
	if err := json.NewEncoder(&input).Encode(map[string]string{
		"source": reconcileScope.Source, "sensor_id": reconcileScope.SensorID, "campus_id": reconcileScope.CampusID,
		"access_domain": reconcileScope.AccessDomain, "timestamp": reconcileObserved.Format(time.RFC3339Nano), "entity_role": "endpoint",
		"account_id": account, "session_id": sessionID, "ip": ip, "session_status": "reconcile", "action": "reconcile",
		"heartbeat_interval_seconds": strconv.Itoa(interval), "reconcile_interval_seconds": strconv.Itoa(interval),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := identityadapter.Convert(&input, &output, identityadapter.Options{Source: reconcileScope.Source, SensorID: reconcileScope.SensorID}); err != nil {
		t.Fatal(err)
	}
	snapshot := IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: "snapshot-replay", ObservedAt: reconcileObserved, IntervalSeconds: interval}
	decoder := json.NewDecoder(&output)
	for decoder.More() {
		var event normalized.Event
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		snapshot.Events = append(snapshot.Events, event)
	}
	return snapshot
}

// The commit stores, prunes and publishes. It must not write account_sessions: that table carries
// 14 indexes and a per-row trigger, and reconciling every member inside the commit took longer than
// the 90-second request budget on the field. Current membership comes from the snapshot projection.
func TestSnapshotCommitDoesNotWriteAccountSessions(t *testing.T) {
	db, mock := newReconcileMock(t)
	expectSnapshotCommitPrefix(mock)
	mock.ExpectExec(`INSERT INTO identity_full_snapshots`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_snapshot_log`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM identity_full_snapshots WHERE ctid IN`)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM identity_snapshot_log WHERE ctid IN`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO identity_pipeline_scopes\(scope_key`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(snapshotPublishSQL)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if _, err := (&PostgresStore{db: db}).CommitIdentitySnapshot(context.Background(), adapterSnapshot(t, "s1", "a1", "10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
