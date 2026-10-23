package controlplane

import (
	"context"
	"database/sql"
	"proxy-sentinel/internal/store"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/sharedaccess"
)

func TestSharedWakeShadowRecordsProgressWithoutRequeue(t *testing.T) {
	for _, mode := range []string{"shadow", "async"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180}, operations: &operationsState{db: db}}
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT wake_id,cursor_job_id").WillReturnRows(sqlmock.NewRows([]string{"wake_id", "cursor_job_id", "producer_mode", "kind", "origin_xid"}).AddRow(7, "", mode, "identity_ip", 1))
			mock.ExpectQuery("SELECT j.job_id FROM shared_observation_jobs").WillReturnRows(sqlmock.NewRows([]string{"job_id"}).AddRow("job-1"))
			if mode == "async" {
				mock.ExpectExec("(?s)UPDATE shared_observation_jobs j SET revision=revision\\+1.*lease_token=''").WillReturnResult(sqlmock.NewResult(0, 1))
			}
			mock.ExpectExec("UPDATE shared_observation_wakes SET cursor_job_id").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			did, err := s.processSharedObservationWake(context.Background())
			if err != nil || !did {
				t.Fatalf("did=%v err=%v", did, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedWakeEmptyBatchIsConfirmed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180}, operations: &operationsState{db: db}}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT wake_id,cursor_job_id").WillReturnRows(sqlmock.NewRows([]string{"wake_id", "cursor_job_id", "producer_mode", "kind", "origin_xid"}).AddRow(7, "job-1", "async", "identity_ip", 1))
	mock.ExpectQuery("SELECT j.job_id FROM shared_observation_jobs").WillReturnRows(sqlmock.NewRows([]string{"job_id"}))
	mock.ExpectExec("UPDATE shared_observation_wakes SET processed_at").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	did, err := s.processSharedObservationWake(context.Background())
	if err != nil || !did {
		t.Fatalf("did=%v err=%v", did, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedSnapshotIPChangesConfirmInBatches(t *testing.T) {
	for _, mode := range []string{"shadow", "async"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180}, operations: &operationsState{db: db}}
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT wake_id,cursor_job_id").WillReturnRows(sqlmock.NewRows([]string{"wake_id", "cursor_job_id", "producer_mode", "kind", "origin_xid"}).AddRow(12, "", mode, "snapshot_ip", 44))
			mock.ExpectQuery("(?s)WITH picked AS.*lease_token=''").WithArgs(int64(44), mode, 180).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1000))
			mock.ExpectCommit()
			did, err := s.processSharedObservationWake(context.Background())
			if err != nil || !did {
				t.Fatalf("did=%v err=%v", did, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedSnapshotScopeOnlyRechecksUnresolvedJobs(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180}, operations: &operationsState{db: db}}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT wake_id,cursor_job_id").WillReturnRows(sqlmock.NewRows([]string{"wake_id", "cursor_job_id", "producer_mode", "kind", "origin_xid"}).AddRow(8, "", "async", "snapshot_scope", 44))
	mock.ExpectQuery("SELECT source,sensor_id,campus_id,access_domain,covered_to,force_all").WillReturnRows(sqlmock.NewRows([]string{"source", "sensor", "campus", "domain", "covered", "force"}).AddRow("auth", "auth", "ncu", "auth", nil, false))
	mock.ExpectQuery("(?s)j.last_result<>'matched'.*j.revision=j.completed_revision OR j.lease_token<>''").WillReturnRows(sqlmock.NewRows([]string{"job_id", "from", "busy"}).AddRow("unresolved-job", nil, false))
	mock.ExpectExec("UPDATE shared_observation_jobs j SET revision=revision\\+1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE shared_observation_wakes SET cursor_job_id").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	did, err := s.processSharedObservationWake(context.Background())
	if err != nil || !did {
		t.Fatalf("did=%v err=%v", did, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCoverageWakeUsesIdentityReadWindow(t *testing.T) {
	now := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	from := now.Add(-11 * time.Minute)
	boundary := from.Add(-3 * time.Minute)
	old := sql.NullTime{Time: from.Add(-24 * time.Hour), Valid: true}
	if !sharedSnapshotCoverageRelevant(old, from, 60, true, false, true) || !sharedSnapshotCoverageRelevant(old, time.Time{}, 60, true, false, false) {
		t.Fatal("in-flight work and unknown windows must retain their wake")
	}

	for _, tt := range []struct {
		covered                 sql.NullTime
		registered, force, want bool
	}{
		{sql.NullTime{}, true, false, true},
		{sql.NullTime{Time: boundary, Valid: true}, true, false, true},
		{sql.NullTime{Time: boundary.Add(-time.Nanosecond), Valid: true}, true, false, false},
		{sql.NullTime{Time: now.Add(-24 * time.Hour), Valid: true}, false, false, true},
		{sql.NullTime{Time: now.Add(-24 * time.Hour), Valid: true}, true, true, true},
	} {
		if got := sharedSnapshotCoverageRelevant(tt.covered, from, 60, tt.registered, tt.force, false); got != tt.want {
			t.Fatalf("case=%+v got=%t", tt, got)
		}
	}
}

func TestHistoricalSnapshotCoverageAdvancesWithoutRequeue(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := store.IdentityScope{Source: "auth", SensorID: "auth", CampusID: "ncu", AccessDomain: "auth"}
	s := &Server{operations: &operationsState{db: db}, identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT wake_id,cursor_job_id").WillReturnRows(sqlmock.NewRows([]string{"id", "cursor", "mode", "kind", "xid"}).AddRow(8, "", "async", "snapshot_scope", 44))
	mock.ExpectQuery("SELECT source,sensor_id,campus_id,access_domain,covered_to,force_all").WithArgs(int64(8)).WillReturnRows(sqlmock.NewRows([]string{"source", "sensor", "campus", "domain", "covered", "force"}).AddRow("auth", "auth", "ncu", "auth", time.Now().Add(-2*time.Hour), false))
	mock.ExpectQuery("SELECT j.job_id,j.last_document").WillReturnRows(sqlmock.NewRows([]string{"id", "from", "busy"}).AddRow("current", time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339Nano), false))
	mock.ExpectExec("UPDATE shared_observation_wakes SET cursor_job_id").WithArgs(int64(8), "current", 0, 0).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	did, err := s.processSharedObservationWake(context.Background())
	if !did || err != nil {
		t.Fatalf("did=%t err=%v", did, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
