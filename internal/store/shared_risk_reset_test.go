package store

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestResetSharedRiskTestDataStopsWhenHumanStateExists(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"actions", "comments", "labels"}).AddRow(0, 1, 0))
	mock.ExpectRollback()
	_, err = (&PostgresStore{db: db}).ResetSharedRiskTestData(context.Background())
	if err == nil || !strings.Contains(err.Error(), "case_comments=1") {
		t.Fatalf("reset did not stop at safety guard: %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
