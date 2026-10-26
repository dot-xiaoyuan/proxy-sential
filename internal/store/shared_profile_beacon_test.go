package store

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// A finished job must not write the singleton runtime row. Every worker updating that one row
// queued on its lock: 3.8 million per-job updates cost the most database time on the field.
func TestFinishedSharedProfileJobDoesNotWriteRuntimeRow(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL synchronous_commit = off`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE shared_device_profile_jobs SET processed_generation`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &DBStore{pg: &PostgresStore{db: db}}
	job := sharedDeviceProfileJob{SubjectKey: "subject-1", DirtyGeneration: 3, LeaseOwner: "worker-1"}
	if err := store.finishSharedDeviceProfileJob(context.Background(), job, nil); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if got := store.pg.profileBeacon.pendingJobs; got != 1 {
		t.Fatalf("pending jobs=%d want 1 buffered in memory", got)
	}
}

func TestUnchangedProfileAckCommitFailureIsNotReportedAsSuccess(t *testing.T) {
	db, mock := newReconcileMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL synchronous_commit = off`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE shared_device_profile_jobs SET processed_generation`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errors.New("commit failed"))
	store := &DBStore{pg: &PostgresStore{db: db}}
	job := sharedDeviceProfileJob{SubjectKey: "subject-1", DirtyGeneration: 3, LeaseOwner: "worker-1"}
	if err := store.finishSharedDeviceProfileJob(context.Background(), job, nil); err == nil {
		t.Fatal("unknown completion commit was reported as durable success")
	}
	if got := store.pg.profileBeacon.pendingJobs; got != 0 {
		t.Fatalf("successful completions=%d after failed commit", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Many finished jobs produce one flush statement carrying the total, not one statement per job.
func TestBeaconFlushWritesOneStatementForManyJobs(t *testing.T) {
	db, mock := newReconcileMock(t)
	pg := &PostgresStore{db: db}
	for i := 0; i < 1000; i++ {
		pg.profileBeacon.success()
	}
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL synchronous_commit = off`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE shared_device_profile_runtime SET last_success_at=now(),`)).
		WithArgs(int64(1000), "", false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := pg.flushSharedProfileBeacon(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The latest error wins within an interval, and a later success clears it.
func TestBeaconKeepsLatestErrorAndSuccessClearsIt(t *testing.T) {
	var b sharedProfileBeacon
	b.failure("first")
	b.failure("second")
	jobs, text, changed := b.take()
	if jobs != 0 || text != "second" || !changed {
		t.Fatalf("take=%d %q %t want 0 second true", jobs, text, changed)
	}
	b.failure("third")
	b.success()
	jobs, text, changed = b.take()
	if jobs != 1 || text != "" || !changed {
		t.Fatalf("after success take=%d %q %t want 1 empty true", jobs, text, changed)
	}
}

// If the flush fails, counts and the error are restored so nothing is lost.
func TestBeaconRestoresStateWhenFlushFails(t *testing.T) {
	db, mock := newReconcileMock(t)
	pg := &PostgresStore{db: db}
	pg.profileBeacon.success()
	pg.profileBeacon.success()
	mock.ExpectBegin().WillReturnError(errors.New("connection refused"))
	if err := pg.flushSharedProfileBeacon(context.Background()); err == nil {
		t.Fatal("flush error swallowed")
	}
	jobs, _, _ := pg.profileBeacon.take()
	if jobs != 2 {
		t.Fatalf("restored jobs=%d want 2", jobs)
	}
}

// With nothing pending the flush is a no-op: an idle heartbeat must not cost a write per tick
// unless it is due to refresh last_success_at.
func TestBeaconFlushWithNothingPendingStillHeartbeats(t *testing.T) {
	db, mock := newReconcileMock(t)
	pg := &PostgresStore{db: db}
	mock.ExpectBegin()
	mock.ExpectExec(`SET LOCAL synchronous_commit = off`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE shared_device_profile_runtime SET last_success_at=now(),`)).
		WithArgs(int64(0), "", false).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := pg.flushSharedProfileBeacon(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
