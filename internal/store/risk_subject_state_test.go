package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/risk"
)

func TestStreamRiskSubjectStateDistinguishesProcessingFromCurrent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	dirty := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	observed := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Microsecond)
	snapshot := risk.Snapshot{IP: "192.0.2.8", Score: 70, Level: "high", UpdatedAt: observed.Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(snapshot)
	semantic := snapshot
	semantic.UpdatedAt = ""
	hash, _ := riskJSONHash(semantic)
	rows := func(dirtyValue any) *sqlmock.Rows {
		return sqlmock.NewRows([]string{"accepted_after", "first_dirty_at", "snapshot", "observed_at", "content_sha256"}).
			AddRow(cutoff, dirtyValue, raw, observed, hash)
	}
	mock.ExpectQuery(`WITH cut AS`).WithArgs("sensor-a", "ip", snapshot.IP).WillReturnRows(rows(dirty))
	store := &PostgresStore{db: db}
	processing, err := store.GetStreamRiskSubjectState(context.Background(), "sensor-a", "ip", snapshot.IP)
	if err != nil || processing.State != "processing" || processing.Snapshot != nil || processing.PendingSince == nil {
		t.Fatalf("pending generation exposed a stale current result: %+v %v", processing, err)
	}
	mock.ExpectQuery(`WITH cut AS`).WithArgs("sensor-a", "ip", snapshot.IP).WillReturnRows(rows(nil))
	current, err := store.GetStreamRiskSubjectState(context.Background(), "sensor-a", "ip", snapshot.IP)
	if err != nil || current.State != "current" || current.Snapshot == nil || current.Snapshot.Score != 70 {
		t.Fatalf("current result was hidden: %+v %v", current, err)
	}
	mock.ExpectQuery(`WITH cut AS`).WithArgs("sensor-a", "ip", snapshot.IP).WillReturnRows(
		sqlmock.NewRows([]string{"accepted_after", "first_dirty_at", "snapshot", "observed_at", "content_sha256"}).
			AddRow(cutoff, nil, nil, nil, nil))
	absent, err := store.GetStreamRiskSubjectState(context.Background(), "sensor-a", "ip", snapshot.IP)
	if err != nil || absent.State != "no_record" || absent.Snapshot != nil {
		t.Fatalf("no risk interpretation was conflated with processing: %+v %v", absent, err)
	}
	oldObserved := time.Now().UTC().Add(-11 * time.Minute).Truncate(time.Microsecond)
	oldSnapshot := snapshot
	oldSnapshot.UpdatedAt = oldObserved.Format(time.RFC3339Nano)
	oldRaw, _ := json.Marshal(oldSnapshot)
	mock.ExpectQuery(`WITH cut AS`).WithArgs("sensor-a", "ip", snapshot.IP).WillReturnRows(
		sqlmock.NewRows([]string{"accepted_after", "first_dirty_at", "snapshot", "observed_at", "content_sha256"}).
			AddRow(cutoff, nil, oldRaw, oldObserved, hash))
	expired, err := store.GetStreamRiskSubjectState(context.Background(), "sensor-a", "ip", snapshot.IP)
	if err != nil || expired.State != "expired" || expired.Snapshot != nil {
		t.Fatalf("expired interpretation was presented as current: %+v %v", expired, err)
	}
	mock.ExpectQuery(`WITH cut AS`).WithArgs("sensor-a", "ip", snapshot.IP).WillReturnRows(
		sqlmock.NewRows([]string{"accepted_after", "first_dirty_at", "snapshot", "observed_at", "content_sha256"}))
	notStarted, err := store.GetStreamRiskSubjectState(context.Background(), "sensor-a", "ip", snapshot.IP)
	if err != nil || notStarted.State != "not_started" {
		t.Fatalf("missing cutover was presented as no record: %+v %v", notStarted, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
