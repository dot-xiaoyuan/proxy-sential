package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStreamRiskCutoverStatusKeepsCancellationSeparateFromPending(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Date(2026, 10, 26, 2, 24, 31, 0, time.UTC)
	audited := cutoff.Add(8 * time.Second)
	oldest := cutoff.Add(time.Minute)
	mock.ExpectQuery(`SELECT cancel_id,accepted_after,canceled_subjects,created_at`).WithArgs("sensor-a").
		WillReturnRows(sqlmock.NewRows([]string{"cancel_id", "accepted_after", "canceled_subjects", "created_at"}).
			AddRow("audit-1", cutoff, int64(40504), audited))
	mock.ExpectQuery(`SELECT count\(\*\),`).WithArgs("sensor-a", cutoff).
		WillReturnRows(sqlmock.NewRows([]string{"pending", "older", "oldest"}).AddRow(int64(12), int64(3), oldest))
	status, active, err := (&PostgresStore{db: db}).GetStreamRiskCutoverStatus(context.Background(), "sensor-a")
	if err != nil || !active || status.CanceledSubjects != 40504 || status.PendingSubjects != 12 ||
		status.PendingOlderThan5Sec != 3 || status.OldestPendingAt == nil || !status.OldestPendingAt.Equal(oldest) {
		t.Fatalf("cutover audit or pending work was lost: %+v active=%v err=%v", status, active, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
