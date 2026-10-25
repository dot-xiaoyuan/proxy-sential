package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRiskDirtyQueueClaimsAndAcknowledgesOnlyClaimedGeneration(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	observed := time.Now().UTC().Truncate(time.Second)
	mock.ExpectQuery(`WITH picked AS`).WithArgs("sensor-a", 128).WillReturnRows(
		sqlmock.NewRows([]string{"sensor_id", "subject_type", "subject_id", "claimed_generation", "last_observed_at", "first_dirty_at"}).AddRow("sensor-a", "ip", "192.0.2.8", int64(47), observed, observed))
	s := &DBStore{pg: &PostgresStore{db: db}}
	claims, err := s.ClaimRiskSubjects(context.Background(), "sensor-a", 128)
	if err != nil || len(claims) != 1 || claims[0].Generation != 47 {
		t.Fatalf("incorrect bounded risk claim: %+v %v", claims, err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(`DELETE FROM risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE risk_feature_dirty_subjects`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	if err := s.AckRiskSubjects(context.Background(), claims); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRiskExpiryOnlyQueuesBoundedStaleCurrentSubjects(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	before := time.Now().UTC().Add(-10 * time.Minute)
	mock.ExpectExec(`WITH expired AS`).WithArgs("sensor-a", before, 64).WillReturnResult(sqlmock.NewResult(0, 2))
	store := &DBStore{pg: &PostgresStore{db: db}}
	if err := store.QueueExpiredStreamRiskSubjects(context.Background(), "sensor-a", before, 64); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
