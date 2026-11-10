package main

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCloseStaleFileCutoverClosesActiveEpoch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT state FROM stream_source_cutovers").
		WithArgs("old-epoch", "device-signals", "/signals/flow-syn.jsonl").
		WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("active"))
	mock.ExpectExec("UPDATE stream_source_cutovers SET state='closed_cancelled_unprocessed'").
		WithArgs("old-epoch", "device-signals", "/signals/flow-syn.jsonl").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err = closeStaleFileCutover(context.Background(), db, "device-signals", "/signals/flow-syn.jsonl", "old-epoch", "new-epoch"); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseStaleFileCutoverRejectsNonActiveEpoch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT state FROM stream_source_cutovers").
		WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("closed"))
	mock.ExpectRollback()
	if err = closeStaleFileCutover(context.Background(), db, "device-signals", "/p", "old", "new"); err == nil {
		t.Fatal("non-active cutover must not be replaced")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
