package controlplane

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// A completed upload supersedes the unfinished uploads of the same scope that started before it; their
// chunks (whole-inventory copies) go at once instead of waiting 24 hours.
func TestSupersededUploadsAreDeletedOnCompletion(t *testing.T) {
	for _, required := range []string{
		"DELETE FROM identity_snapshot_uploads o USING identity_snapshot_uploads c",
		"c.upload_id=$1",
		"o.source=c.source AND o.sensor_id=c.sensor_id AND o.campus_id=c.campus_id AND o.access_domain=c.access_domain",
		"o.status<>'completed'",
		"o.created_at<c.created_at",
	} {
		if !strings.Contains(supersededUploadsDeleteSQL, required) {
			t.Fatalf("cleanup lacks %q: %s", required, supersededUploadsDeleteSQL)
		}
	}
}

func TestCompletedSnapshotChunkCleanupIsBoundedAndRetryable(t *testing.T) {
	if _, err := pruneCompletedIdentitySnapshotChunks(context.Background(), nil, 4); err == nil {
		t.Fatal("cleanup accepted a missing database")
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := pruneCompletedIdentitySnapshotChunks(context.Background(), db, 17); err == nil {
		t.Fatal("cleanup accepted an unbounded claim")
	}
	mock.ExpectExec("WITH selected AS").WithArgs(4).WillReturnResult(sqlmock.NewResult(0, 4))
	removed, err := pruneCompletedIdentitySnapshotChunks(context.Background(), db, 4)
	if err != nil || removed != 4 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(completedSnapshotChunkPruneSQL, "u.status='completed'") ||
		!strings.Contains(completedSnapshotChunkPruneSQL, "u.completed_at<now()-interval '1 minute'") ||
		!strings.Contains(completedSnapshotChunkPruneSQL, "LIMIT $1 FOR UPDATE OF c SKIP LOCKED") {
		t.Fatal("cleanup may remove uncommitted snapshots or more than one bounded claim")
	}
}
