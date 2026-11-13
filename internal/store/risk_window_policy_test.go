package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRiskWindowRegistrationRejectsUnsafeChanges(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	backend := &DBStore{pg: &PostgresStore{db: db}}
	ctx := context.Background()
	if err := backend.RegisterStreamRiskWindow(ctx, "sensor-a", 30*time.Minute+time.Millisecond); err == nil {
		t.Fatal("fractional window cannot be represented in the policy")
	}
	mock.ExpectQuery(`INSERT INTO stream_risk_window_policies`).WithArgs("sensor-a", 1800, 45).
		WillReturnRows(sqlmock.NewRows([]string{"safe_skip_seconds"}).AddRow(1800))
	if err := backend.RegisterStreamRiskWindow(ctx, "sensor-a", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`INSERT INTO stream_risk_window_policies`).WithArgs("sensor-a", 3600, 45).
		WillReturnRows(sqlmock.NewRows([]string{"safe_skip_seconds"}))
	if err := backend.RegisterStreamRiskWindow(ctx, "sensor-a", time.Hour); err == nil {
		t.Fatal("wider worker was accepted after packet wakes may have been omitted")
	}
	mock.ExpectQuery(`FROM stream_risk_window_policies WHERE sensor_id`).WithArgs("sensor-a").
		WillReturnRows(sqlmock.NewRows([]string{"active_window_seconds", "safe_skip_seconds", "leased"}).AddRow(1800, 1800, true))
	if err := backend.CheckStreamRiskWindow(ctx, "sensor-a", time.Hour); err == nil {
		t.Fatal("one-shot wider worker bypassed the recorded skip horizon")
	}
	mock.ExpectQuery(`FROM stream_risk_window_policies WHERE sensor_id`).WithArgs("sensor-a").
		WillReturnRows(sqlmock.NewRows([]string{"active_window_seconds", "safe_skip_seconds", "leased"}).AddRow(1800, 1800, true))
	if err := backend.CheckStreamRiskWindow(ctx, "sensor-a", 10*time.Minute); err == nil {
		t.Fatal("one-shot worker conflicted with a live, different window")
	}
	mock.ExpectQuery(`FROM stream_risk_window_policies WHERE sensor_id`).WithArgs("sensor-a").
		WillReturnRows(sqlmock.NewRows([]string{"active_window_seconds", "safe_skip_seconds", "leased"}).AddRow(600, 1800, false))
	if err := backend.CheckStreamRiskWindow(ctx, "sensor-a", 30*time.Minute); err != nil {
		t.Fatalf("a safe one-shot window after lease expiry was rejected: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
