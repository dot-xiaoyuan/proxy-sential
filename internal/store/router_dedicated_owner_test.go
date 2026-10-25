package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDedicatedRouterOwnerRequiresSameSensorAndRecentSuccess(t *testing.T) {
	at := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, sensor, lastError string
		success                 time.Time
		valid                   bool
	}{
		{"healthy", "site-sensor", "", at.Add(-time.Minute), true},
		{"other sensor", "other-sensor", "", at.Add(-time.Minute), false},
		{"stale", "site-sensor", "", at.Add(-3 * time.Minute), false},
		{"failed", "site-sensor", "storage error", at.Add(-time.Minute), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`SELECT sensor_id,last_success_at,last_error FROM router_recognition_state`).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "last_success_at", "last_error"}).AddRow(test.sensor, test.success, test.lastError))
			if test.valid {
				mock.ExpectQuery(`SELECT EXISTS.*stream_source_cutovers`).WithArgs("site-sensor").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			}
			err = (&DBStore{pg: &PostgresStore{db: db}}).DedicatedRouterObservationsHealthy(context.Background(), "site-sensor", at)
			if (err == nil) != test.valid {
				t.Fatalf("owner validation = %v, want valid=%t", err, test.valid)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDedicatedRouterOwnerRequiresHealthyStreamCursorWhenSourceActive(t *testing.T) {
	at := time.Date(2026, 10, 25, 8, 36, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		success time.Time
		message string
		wantOK  bool
	}{
		{"current", at.Add(-time.Minute), "", true},
		{"stale", at.Add(-3 * time.Minute), "", false},
		{"failed", at.Add(-time.Minute), "index gap", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`SELECT sensor_id,last_success_at,last_error FROM router_recognition_state`).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "last_success_at", "last_error"}).AddRow("site-sensor", at.Add(-time.Minute), ""))
			mock.ExpectQuery(`SELECT EXISTS.*stream_source_cutovers`).WithArgs("site-sensor").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
			mock.ExpectQuery(`SELECT last_success_at,last_error FROM stream_router_recognition_state`).WithArgs("site-sensor").WillReturnRows(sqlmock.NewRows([]string{"last_success_at", "last_error"}).AddRow(test.success, test.message))
			err = (&DBStore{pg: &PostgresStore{db: db}}).DedicatedRouterObservationsHealthy(context.Background(), "site-sensor", at)
			if (err == nil) != test.wantOK {
				t.Fatalf("stream owner validation = %v, want valid=%t", err, test.wantOK)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
