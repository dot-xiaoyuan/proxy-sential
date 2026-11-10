package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDiscoveryTrendsFillsMissingDays(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	today := time.Now().UTC().Format("2006-01-02")
	mock.ExpectQuery(`SELECT to_char\(first_seen AT TIME ZONE`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"day", "new", "typed"}).
			AddRow(today, 4, 3))
	mock.ExpectQuery(`SELECT coalesce\(role,''\)`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"device_type", "count"}).
			AddRow("mobile", 3).AddRow("camera", 1))
	result, err := (Repository{DB: db}).DiscoveryTrends(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Days) != 7 {
		t.Fatalf("days=%d", len(result.Days))
	}
	if result.Days[6].Date != today || result.Days[6].New != 4 || result.Days[6].Typed != 3 {
		t.Fatalf("today=%+v", result.Days[6])
	}
	if result.Days[0].New != 0 {
		t.Fatalf("zero day=%+v", result.Days[0])
	}
	if len(result.TopTypes) != 2 || result.TopTypes[0].DeviceType != "mobile" || result.TopTypes[0].Count != 3 {
		t.Fatalf("top types=%+v", result.TopTypes)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryTrendsRejectsInvalidWindow(t *testing.T) {
	if _, err := (Repository{}).DiscoveryTrends(context.Background(), 0); err == nil {
		t.Fatal("expected error")
	}
	if _, err := (Repository{}).DiscoveryTrends(context.Background(), 31); err == nil {
		t.Fatal("expected error")
	}
}
