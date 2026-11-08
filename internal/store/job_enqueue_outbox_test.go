package store

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestFlushRecognitionDirtyLogFoldsBatchInOneStatement(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`WITH batch AS \(`).WithArgs(500).WillReturnRows(sqlmock.NewRows([]string{"consumed", "updated"}).AddRow(4, 3))
	consumed, err := (&DBStore{pg: &PostgresStore{db: db}}).flushRecognitionDirtyLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 4 {
		t.Fatalf("consumed=%d", consumed)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFlushSharedProfileDirtyLogFoldsBatchInOneStatement(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`WITH batch AS \(`).WithArgs(500).WillReturnRows(sqlmock.NewRows([]string{"consumed", "updated"}).AddRow(2, 2))
	consumed, err := (&DBStore{pg: &PostgresStore{db: db}}).flushSharedProfileDirtyLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 2 {
		t.Fatalf("consumed=%d", consumed)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestJobEnqueueLogRetentionDeletesBothLogs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec(`DELETE FROM endpoint_recognition_dirty_log`).WillReturnResult(sqlmock.NewResult(0, 3))
	if err = (&DBStore{pg: &PostgresStore{db: db}}).pruneJobEnqueueLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
