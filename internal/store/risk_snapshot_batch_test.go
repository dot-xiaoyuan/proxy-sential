package store

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/risk"
)

func TestRiskSnapshotBatchWritesBySubjectSet(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO risk_snapshots`).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`INSERT INTO risk_snapshot_history_heads`).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	items := []risk.Snapshot{
		{IP: "192.0.2.1", Score: 50, UpdatedAt: "2026-10-25T02:00:00Z"},
		{IP: "192.0.2.2", Score: 70, UpdatedAt: "2026-10-25T02:00:00Z"},
	}
	if err := (&PostgresStore{db: db}).WriteRiskSnapshots(context.Background(), items); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRiskSnapshotBatchPreservesRepeatedSubjectOrder(t *testing.T) {
	runs, err := partitionRiskSnapshots([]risk.Snapshot{
		{IP: "192.0.2.1", Score: 10}, {IP: "192.0.2.2", Score: 20}, {IP: "192.0.2.1", Score: 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || len(runs[0]) != 2 || len(runs[1]) != 1 || runs[1][0].Score != 30 {
		t.Fatalf("repeated subject order lost: %#v", runs)
	}
}
