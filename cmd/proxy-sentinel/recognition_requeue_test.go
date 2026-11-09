package main

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRequeueCurrentEndpointsBatchesByKeyset(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT endpoint_id FROM endpoint_entities").WithArgs("", 2).
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id"}).AddRow("a").AddRow("b"))
	mock.ExpectExec("INSERT INTO endpoint_recognition_dirty_log").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 2))
	mock.ExpectQuery("SELECT endpoint_id FROM endpoint_entities").WithArgs("b", 2).
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id"}).AddRow("c"))
	mock.ExpectExec("INSERT INTO endpoint_recognition_dirty_log").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(2, 1))
	total, err := requeueCurrentEndpoints(context.Background(), db, 2, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("total=%d", total)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRequeueCurrentEndpointsRespectsLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT endpoint_id FROM endpoint_entities").WithArgs("", 1).
		WillReturnRows(sqlmock.NewRows([]string{"endpoint_id"}).AddRow("a"))
	mock.ExpectExec("INSERT INTO endpoint_recognition_dirty_log").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	total, err := requeueCurrentEndpoints(context.Background(), db, 2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("total=%d", total)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRequeueCurrentEndpointsRejectsInvalidBatch(t *testing.T) {
	if _, err := requeueCurrentEndpoints(context.Background(), nil, 0, 0, time.Second); err == nil {
		t.Fatal("accepted zero batch size")
	}
	if _, err := requeueCurrentEndpoints(context.Background(), nil, 5001, 0, time.Second); err == nil {
		t.Fatal("accepted oversized batch size")
	}
}
