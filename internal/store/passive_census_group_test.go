package store

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func censusGroupTask(id int64) censusPendingBatch {
	now := time.Date(2026, 11, 12, 4, 0, 0, 0, time.UTC)
	return censusPendingBatch{ID: id, SensorID: "s", ScopeVersion: "scope", Owner: "group-owner", FirstSourceAt: now, LastSourceAt: now, FirstEnqueuedAt: now}
}

func TestCensusGroupBoundsAndIdentity(t *testing.T) {
	if err := validateCensusGroup([]censusPendingBatch{censusGroupTask(1), censusGroupTask(2)}); err != nil {
		t.Fatal(err)
	}
	for name, tasks := range map[string][]censusPendingBatch{
		"duplicate": {censusGroupTask(1), censusGroupTask(1)},
		"scope":     {censusGroupTask(1), func() censusPendingBatch { x := censusGroupTask(2); x.ScopeVersion = "other"; return x }()},
		"bytes":     {func() censusPendingBatch { x := censusGroupTask(1); x.PayloadBytes = censusGroupMaxBytes + 1; return x }()},
		"facts": {func() censusPendingBatch {
			x := censusGroupTask(1)
			x.Payload.Current = make([]censusIdentifierSpan, censusGroupMaxFacts+1)
			return x
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			if validateCensusGroup(tasks) == nil {
				t.Fatal("unsafe group accepted")
			}
		})
	}
	many := make([]censusPendingBatch, censusGroupMaxJobs+1)
	for i := range many {
		many[i] = censusGroupTask(int64(i + 1))
	}
	if validateCensusGroup(many) == nil {
		t.Fatal("job budget ignored")
	}
}

func TestCensusGroupLeaseChangeRollsBackAll(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	tasks := []censusPendingBatch{censusGroupTask(1), censusGroupTask(2)}
	m.ExpectBegin()
	m.ExpectExec("pg_advisory_xact_lock").WithArgs("s").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery("SELECT id,lease_owner,sensor_id,scope_version FROM passive_census_pending_batches").WillReturnRows(sqlmock.NewRows([]string{"id", "lease_owner", "sensor_id", "scope_version"}).AddRow(1, "group-owner", "s", "scope").AddRow(2, "another-owner", "s", "scope"))
	m.ExpectRollback()
	err = s.applyPassiveCensusGroup(context.Background(), tasks)
	var failure *censusGroupFailure
	if !errors.As(err, &failure) || failure.TaskID != 2 {
		t.Fatalf("wrong failure: %v", err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCensusGroupEmptyJobsCommitTogether(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	tasks := []censusPendingBatch{censusGroupTask(2), censusGroupTask(1)}
	m.ExpectBegin()
	m.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery("SELECT id,lease_owner,sensor_id,scope_version FROM passive_census_pending_batches").WillReturnRows(sqlmock.NewRows([]string{"id", "lease_owner", "sensor_id", "scope_version"}).AddRow(1, "group-owner", "s", "scope").AddRow(2, "group-owner", "s", "scope"))
	m.ExpectQuery("SELECT scope_version FROM passive_census_runtime").WithArgs("s").WillReturnRows(sqlmock.NewRows([]string{"scope_version"}).AddRow("scope"))
	m.ExpectExec("UPDATE passive_census_pending_batches SET processed_at").WillReturnResult(sqlmock.NewResult(0, 2))
	m.ExpectQuery(regexp.QuoteMeta("SELECT min(first_source_at) FROM passive_census_pending_batches")).WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(nil))
	m.ExpectExec("UPDATE passive_census_runtime SET available_from").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	if err = s.applyPassiveCensusGroup(context.Background(), tasks); err != nil {
		t.Fatal(err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func censusCandidateColumns() []string {
	return []string{"id", "sensor_id", "scope_version", "first_source_at", "last_source_at", "first_enqueued_at", "attempts", "payload_bytes", "valid_shape", "current_count", "bucket_count", "binding_count"}
}

func TestCensusGroupClaimBoundsBeforeReadingBodies(t *testing.T) {
	for _, kind := range []string{"bytes", "facts"} {
		t.Run(kind, func(t *testing.T) {
			db, m, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
			at := censusGroupTask(1).FirstSourceAt
			size, count := censusGroupMaxBytes-1, 0
			if kind == "facts" {
				size, count = 100, censusGroupMaxFacts
			}
			m.ExpectBegin()
			m.ExpectQuery("SELECT id,sensor_id,scope_version.*octet_length").WithArgs("s").WillReturnRows(sqlmock.NewRows(censusCandidateColumns()).AddRow(1, "s", "scope", at, at, at, 0, size, true, count, 0, 0).AddRow(2, "s", "scope", at, at, at, 0, 100, true, 1, 0, 0))
			// The second candidate must remain unleased and its body must not cross
			// the DB connection simply because the metadata page included it.
			m.ExpectQuery("UPDATE passive_census_pending_batches SET lease_owner").WithArgs("{1}", "group-owner").WillReturnRows(sqlmock.NewRows([]string{"id", "payload"}).AddRow(1, []byte(`{}`)))
			m.ExpectCommit()
			tasks, err := s.claimPassiveCensusGroup(context.Background(), "group-owner")
			if err != nil || len(tasks) != 1 || tasks[0].ID != 1 {
				t.Fatalf("claim=%+v err=%v", tasks, err)
			}
			if err = m.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCensusGroupOversizeFirstJobGetsFailureLeaseWithoutBody(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	at := censusGroupTask(1).FirstSourceAt
	m.ExpectBegin()
	m.ExpectQuery("SELECT id,sensor_id,scope_version.*octet_length").WillReturnRows(sqlmock.NewRows(censusCandidateColumns()).AddRow(1, "s", "scope", at, at, at, 0, censusGroupMaxBytes+1, true, 1, 0, 0))
	m.ExpectExec("UPDATE passive_census_pending_batches SET lease_owner").WithArgs(int64(1), "group-owner").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	tasks, err := s.claimPassiveCensusGroup(context.Background(), "group-owner")
	var failure *censusGroupFailure
	if len(tasks) != 1 || !errors.As(err, &failure) || failure.TaskID != 1 {
		t.Fatalf("claim=%+v err=%v", tasks, err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCensusGroupClaimDecodeFailureKeepsAllLeasesForRecovery(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	at := censusGroupTask(1).FirstSourceAt
	m.ExpectBegin()
	m.ExpectQuery("SELECT id,sensor_id,scope_version.*octet_length").WillReturnRows(sqlmock.NewRows(censusCandidateColumns()).AddRow(1, "s", "scope", at, at, at, 0, 100, true, 0, 0, 0).AddRow(2, "s", "scope", at, at, at, 0, 100, true, 1, 0, 0))
	m.ExpectQuery("UPDATE passive_census_pending_batches SET lease_owner").WithArgs("{1,2}", "group-owner").WillReturnRows(sqlmock.NewRows([]string{"id", "payload"}).AddRow(1, []byte(`{}`)).AddRow(2, []byte(`{"current":[{"first_seen":"not-a-time"}]}`)))
	m.ExpectCommit()
	tasks, err := s.claimPassiveCensusGroup(context.Background(), "group-owner")
	var failure *censusGroupFailure
	if len(tasks) != 2 || !errors.As(err, &failure) || failure.TaskID != 2 {
		t.Fatalf("claim=%+v err=%v", tasks, err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCensusGroupFailureRollsBackAndReleasesOnlyOtherJobs(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	tasks := []censusPendingBatch{censusGroupTask(1), censusGroupTask(2)}
	for i := range tasks {
		tasks[i].Payload.Current = []censusIdentifierSpan{{}}
	}
	m.ExpectBegin()
	m.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery("SELECT id,lease_owner,sensor_id,scope_version FROM passive_census_pending_batches").WillReturnRows(sqlmock.NewRows([]string{"id", "lease_owner", "sensor_id", "scope_version"}).AddRow(1, "group-owner", "s", "scope").AddRow(2, "group-owner", "s", "scope"))
	m.ExpectQuery("SELECT scope_version FROM passive_census_runtime").WillReturnRows(sqlmock.NewRows([]string{"scope_version"}).AddRow("scope"))
	m.ExpectExec("INSERT INTO passive_census_identifier_current").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec("INSERT INTO passive_census_identifier_current").WillReturnError(errors.New("injected second job failure"))
	m.ExpectRollback()
	err = s.applyPassiveCensusGroup(context.Background(), tasks)
	var failure *censusGroupFailure
	if !errors.As(err, &failure) || failure.TaskID != 2 {
		t.Fatalf("wrong failure: %v", err)
	}
	m.ExpectExec("UPDATE passive_census_pending_batches SET lease_owner='',lease_until='-infinity'").WithArgs("{1}", "group-owner").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec("UPDATE passive_census_pending_batches SET lease_owner='',lease_until=now").WithArgs(int64(2), "group-owner", sqlmock.AnyArg(), "5s").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec("UPDATE passive_census_runtime SET failed_batches").WithArgs("s", sqlmock.AnyArg(), tasks[1].FirstSourceAt).WillReturnResult(sqlmock.NewResult(0, 1))
	s.failPassiveCensusGroup(context.Background(), tasks, err)
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCensusGroupReclaimedLeaseRejectsStaleWorker(t *testing.T) {
	// Expiry/reclaim uses a new group owner. The stale group is never permitted
	// to commit data even if its process is still alive after cancellation.
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	task := censusGroupTask(1)
	m.ExpectBegin()
	m.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery("SELECT id,lease_owner,sensor_id,scope_version FROM passive_census_pending_batches").WillReturnRows(sqlmock.NewRows([]string{"id", "lease_owner", "sensor_id", "scope_version"}).AddRow(1, "census-new-claim-owner", "s", "scope"))
	m.ExpectRollback()
	if s.applyPassiveCensusGroup(context.Background(), []censusPendingBatch{task}) == nil {
		t.Fatal("stale lease committed")
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCensusGroupInterruptedClaimRollsBackWithoutPayloadTransfer(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	at := censusGroupTask(1).FirstSourceAt
	m.ExpectBegin()
	m.ExpectQuery("SELECT id,sensor_id,scope_version.*octet_length").WillReturnRows(sqlmock.NewRows(censusCandidateColumns()).AddRow(1, "s", "scope", at, at, at, 0, 100, true, 0, 0, 0).RowError(0, context.Canceled))
	m.ExpectRollback()
	tasks, err := s.claimPassiveCensusGroup(context.Background(), "group-owner")
	if len(tasks) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("claim=%+v err=%v", tasks, err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCensusGroupCommitFailureCannotReportCompleted(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db, sensorID: "s"}}
	tasks := []censusPendingBatch{censusGroupTask(1), censusGroupTask(2)}
	m.ExpectBegin()
	m.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery("SELECT id,lease_owner,sensor_id,scope_version FROM passive_census_pending_batches").WillReturnRows(sqlmock.NewRows([]string{"id", "lease_owner", "sensor_id", "scope_version"}).AddRow(1, "group-owner", "s", "scope").AddRow(2, "group-owner", "s", "scope"))
	m.ExpectQuery("SELECT scope_version FROM passive_census_runtime").WillReturnRows(sqlmock.NewRows([]string{"scope_version"}).AddRow("scope"))
	m.ExpectExec("UPDATE passive_census_pending_batches SET processed_at").WillReturnResult(sqlmock.NewResult(0, 2))
	m.ExpectQuery("SELECT min\\(first_source_at\\) FROM passive_census_pending_batches").WillReturnRows(sqlmock.NewRows([]string{"min"}).AddRow(tasks[0].FirstSourceAt.Add(-time.Hour)))
	m.ExpectExec("UPDATE passive_census_runtime SET available_from").WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit().WillReturnError(context.DeadlineExceeded)
	err = s.applyPassiveCensusGroup(context.Background(), tasks)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("commit failure hidden: %v", err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
