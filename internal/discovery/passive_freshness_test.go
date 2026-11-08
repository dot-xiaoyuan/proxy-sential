package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPassiveDiscoveryFreshnessStates(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name       string
		cursor     any
		lastError  string
		updatedAge time.Duration
		want       string
	}{
		{"ready within holdback", now.Add(-5 * time.Minute), "", time.Minute, "ready"},
		{"delayed beyond threshold", now.Add(-20 * time.Minute), "", time.Minute, "delayed"},
		{"recent failure", now.Add(-5 * time.Minute), "timeout: context deadline exceeded", time.Minute, "failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`FROM passive_discovery_state`).WillReturnRows(sqlmock.NewRows([]string{"cursor_timestamp", "last_success_at", "last_error", "updated_at"}).
				AddRow(tc.cursor, now.Add(-time.Minute), tc.lastError, now.Add(-tc.updatedAge)))
			result := (Repository{DB: db}).PassiveDiscoveryFreshness(context.Background())
			if result == nil || result["status"] != tc.want {
				t.Fatalf("freshness=%v want status %q", result, tc.want)
			}
			if tc.want == "delayed" && result["lag_seconds"].(float64) < 600 {
				t.Fatalf("delayed freshness must expose lag, got %v", result)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPassiveDiscoveryFreshnessOmitsMissingState(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM passive_discovery_state`).WillReturnRows(sqlmock.NewRows([]string{"cursor_timestamp", "last_success_at", "last_error", "updated_at"}).AddRow(nil, nil, "", nil))
	result := (Repository{DB: db}).PassiveDiscoveryFreshness(context.Background())
	if result == nil || result["status"] != "initializing" {
		t.Fatalf("missing cursor must report initializing, got %v", result)
	}
}
