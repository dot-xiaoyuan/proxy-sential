package store

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// Latest run requests must reach the sensor/time index rather than sort the
// entire immutable run history. Database ordering semantics are checked with
// real PostgreSQL in the companion replay.
func TestCollectorRunQueryBoundsEachSensor(t *testing.T) {
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	wanted := errors.New("read cancelled")
	m.ExpectQuery(`FROM sensors.*CROSS JOIN LATERAL`).WithArgs(1).WillReturnError(wanted)
	_, err = (&PostgresStore{db: db}).ListRuns(context.Background(), 1)
	if !errors.Is(err, wanted) {
		t.Fatalf("indexed bounded query missing or error hidden: %v", err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorRunPageQueryBoundsBeforeGlobalSort(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT count\(\*\) FROM collector_runs`).WithArgs("", "%%").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1000000))
	wanted := errors.New("read cancelled")
	mock.ExpectQuery(`FROM sensors.*CROSS JOIN LATERAL`).WithArgs("", "%%", 20, 40).WillReturnError(wanted)
	_, _, err = (&PostgresStore{db: db}).ListRunsPage(context.Background(), Query{Limit: 20, Cursor: 40})
	if !errors.Is(err, wanted) {
		t.Fatalf("page sorted all history before limiting sensors: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
