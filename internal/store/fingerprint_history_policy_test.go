package store

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestFingerprintHistoryDisabledKeepsRealtimeClaims(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_FINGERPRINT_HISTORY_BACKFILL", "false")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db}}
	s.runFingerprintRebuild(context.Background())
	if _, found, err := s.claimRecognitionJob(context.Background(), "recognition-test-3"); err != nil || found {
		t.Fatalf("history worker touched disabled lane: found=%t err=%v", found, err)
	}
	mock.ExpectQuery("WITH picked AS").WithArgs(sqlmock.AnyArg(), 0).
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id", "dirty_generation", "attempts", "lease_owner"}).AddRow("live-endpoint", 7, 0, "live-owner"))
	job, found, err := s.claimRecognitionJob(context.Background(), "recognition-test-0")
	if err != nil || !found || job.EndpointID != "live-endpoint" || job.Historical {
		t.Fatalf("realtime claim was interrupted: job=%+v found=%t err=%v", job, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintHistoryOptInCanResumePendingClaims(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_FINGERPRINT_HISTORY_BACKFILL", "true")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &DBStore{pg: &PostgresStore{db: db}}
	mock.ExpectQuery("WITH picked AS").WithArgs(sqlmock.AnyArg(), 1).
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id", "dirty_generation", "attempts", "lease_owner"}).AddRow("history-endpoint", 7, 0, "history-owner"))
	job, found, err := s.claimRecognitionJob(context.Background(), "recognition-test-3")
	if err != nil || !found || !job.Historical {
		t.Fatalf("explicitly enabled history cannot resume: job=%+v found=%t err=%v", job, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
