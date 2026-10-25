package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRiskFreshCutoverAuditsOnlyPreCutoffDirtySubjects(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	s := &DBStore{pg: &PostgresStore{db: db}}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`LOCK TABLE risk_feature_dirty_subjects`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT accepted_after FROM stream_risk_fresh_cutovers.*ORDER BY accepted_after DESC`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}))
	mock.ExpectQuery(`SELECT count\(\*\),count\(\*\) FILTER .*first_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnRows(sqlmock.NewRows([]string{"count", "stale"}).AddRow(3, 2))
	mock.ExpectExec(`INSERT INTO stream_risk_fresh_cutovers`).WithArgs("sensor-a", "cancel-1", cutoff, int64(3)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO stream_risk_canceled_subjects.*fresh_generation_retained.*first_dirty_at<\$3`).WithArgs("sensor-a", "cancel-1", cutoff).WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects WHERE sensor_id=\$1 AND last_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	count, err := s.StartStreamRiskFreshCutover(context.Background(), "sensor-a", "cancel-1", cutoff)
	if err != nil || count != 3 {
		t.Fatalf("canceled risk subjects not audited: %d %v", count, err)
	}
	mock.ExpectQuery(`SELECT accepted_after FROM stream_risk_fresh_cutovers.*ORDER BY accepted_after DESC`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}).AddRow(cutoff))
	got, err := s.StreamRiskFreshCutoff(context.Background(), "sensor-a")
	if err != nil || !got.Equal(cutoff) {
		t.Fatalf("risk fresh cutoff missing: %s %v", got, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRiskFreshCutoverRollsBackOnAuditMismatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	s := &DBStore{pg: &PostgresStore{db: db}}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`LOCK TABLE risk_feature_dirty_subjects`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT accepted_after FROM stream_risk_fresh_cutovers.*ORDER BY accepted_after DESC`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}))
	mock.ExpectQuery(`SELECT count\(\*\),count\(\*\) FILTER .*first_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnRows(sqlmock.NewRows([]string{"count", "stale"}).AddRow(2, 2))
	mock.ExpectExec(`INSERT INTO stream_risk_fresh_cutovers`).WithArgs("sensor-a", "cancel-1", cutoff, int64(2)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO stream_risk_canceled_subjects.*fresh_generation_retained.*first_dirty_at<\$3`).WithArgs("sensor-a", "cancel-1", cutoff).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects WHERE sensor_id=\$1 AND last_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectRollback()
	if _, err := s.StartStreamRiskFreshCutover(context.Background(), "sensor-a", "cancel-1", cutoff); err == nil {
		t.Fatal("mismatched cancellation audit committed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRiskFreshCutoverRequiresStrictlyNewerGeneration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	prior := cutoff.Add(-time.Minute)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`LOCK TABLE risk_feature_dirty_subjects`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT accepted_after FROM stream_risk_fresh_cutovers.*ORDER BY accepted_after DESC`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}).AddRow(prior))
	mock.ExpectQuery(`SELECT count\(\*\),count\(\*\) FILTER .*first_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnRows(sqlmock.NewRows([]string{"count", "stale"}).AddRow(1, 1))
	mock.ExpectExec(`INSERT INTO stream_risk_fresh_cutovers`).WithArgs("sensor-a", "cancel-2", cutoff, int64(1)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO stream_risk_canceled_subjects.*fresh_generation_retained.*first_dirty_at<\$3`).WithArgs("sensor-a", "cancel-2", cutoff).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects WHERE sensor_id=\$1 AND last_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	store := &PostgresStore{db: db}
	if n, err := store.StartStreamRiskFreshCutover(context.Background(), "sensor-a", "cancel-2", cutoff); err != nil || n != 1 {
		t.Fatalf("second audited generation rejected: %d %v", n, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRiskFreshCutoverKeepsEntireFreshDirtyQueue(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("sensor-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`LOCK TABLE risk_feature_dirty_subjects`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT accepted_after FROM stream_risk_fresh_cutovers.*ORDER BY accepted_after DESC`).WithArgs("sensor-a").WillReturnRows(sqlmock.NewRows([]string{"accepted_after"}))
	mock.ExpectQuery(`SELECT count\(\*\),count\(\*\) FILTER .*first_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnRows(sqlmock.NewRows([]string{"count", "stale"}).AddRow(0, 0))
	mock.ExpectExec(`INSERT INTO stream_risk_fresh_cutovers`).WithArgs("sensor-a", "cancel-fresh", cutoff, int64(0)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO stream_risk_canceled_subjects.*fresh_generation_retained.*first_dirty_at<\$3`).WithArgs("sensor-a", "cancel-fresh", cutoff).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects WHERE sensor_id=\$1 AND last_dirty_at<\$2`).WithArgs("sensor-a", cutoff).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	store := &PostgresStore{db: db}
	if n, err := store.StartStreamRiskFreshCutover(context.Background(), "sensor-a", "cancel-fresh", cutoff); err != nil || n != 0 {
		t.Fatalf("fresh dirty queue was not preserved: %d %v", n, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
