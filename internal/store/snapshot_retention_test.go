package store

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// Only the newest document per scope is kept: older documents go as soon as the projection no longer
// needs them. The metadata log keeps every snapshot for a year.
func TestSnapshotPruneKeepsOnlyLatestDocumentAndYearOfMetadata(t *testing.T) {
	for _, required := range []string{"f.observed_at<$5", "NOT EXISTS (SELECT 1 FROM identity_snapshot_projection_jobs j", "ORDER BY f.observed_at LIMIT $6"} {
		if !strings.Contains(snapshotPruneSQL, required) {
			t.Fatalf("document prune lacks %q: %s", required, snapshotPruneSQL)
		}
	}
	if !strings.Contains(snapshotLogPruneSQL, "observed_at<$5") || !strings.Contains(snapshotLogPruneSQL, "LIMIT $6") {
		t.Fatalf("log prune not bounded: %s", snapshotLogPruneSQL)
	}
	if snapshotMetadataRetention != 365*24*time.Hour {
		t.Fatalf("metadata retention=%s", snapshotMetadataRetention)
	}
	db, mock := newReconcileMock(t)
	snapshot := snapshotWith()
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(snapshotPruneSQL)).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, reconcileObserved, snapshotPruneBatch).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(snapshotLogPruneSQL)).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, reconcileObserved.Add(-snapshotMetadataRetention), snapshotPruneBatch).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = pruneSnapshotsTx(context.Background(), tx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	var _ *sql.Tx = tx
}
