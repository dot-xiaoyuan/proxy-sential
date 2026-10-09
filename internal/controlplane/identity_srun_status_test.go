package controlplane

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/store"
)

func TestSRunIdentityStatusUsesCurrentRegistration(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		age        time.Duration
		interval   int
		registered bool
		state      string
	}{
		{"snapshot before next calibration", 3 * time.Hour, 21600, true, "healthy"},
		{"exact outage boundary", 18 * time.Hour, 21600, true, "interrupted"},
		{"current shorter contract", 3 * time.Hour, 3600, true, "interrupted"},
		{"future observation", -time.Second, 21600, true, "interrupted"},
		{"missing snapshot", 0, 21600, true, "never_seen"},
		{"removed authority", 3 * time.Hour, 21600, false, "unregistered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			s := &Server{operations: &operationsState{db: db}}
			mock.ExpectQuery(`SELECT i.connector_id,i.config_version`).WillReturnRows(sqlmock.NewRows([]string{"connector_id", "config_version", "public_config", "encrypted_token", "endpoint_url", "certificate_pem", "state", "blocker", "observed_at", "last_success_at", "last_attempt_at", "record_count"}))
			rows := sqlmock.NewRows([]string{"interval"})
			if tc.registered {
				rows.AddRow(tc.interval)
			}
			mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs("srun4k:one", "one").WillReturnRows(rows)
			observedAt := now.Add(-tc.age)
			if tc.name == "missing snapshot" {
				observedAt = time.Time{}
			}
			observed := []store.IdentitySourceStatus{{IdentityScope: store.IdentityScope{Source: "srun4k:one", SensorID: "one"}, ObservedAt: observedAt, IntervalSeconds: 604800, State: "healthy", SessionCount: 161, SnapshotID: "preserved"}}
			got, err := s.mergeManagedIdentitySources(context.Background(), observed, now)
			if err != nil || len(got) != 1 || got[0].State != tc.state {
				t.Fatalf("got=%+v err=%v want=%s", got, err, tc.state)
			}
			if tc.registered && got[0].IntervalSeconds != tc.interval {
				t.Fatal("sender freshness overrode current authority")
			}
			if got[0].SnapshotID != "preserved" || got[0].SessionCount != 161 || observed[0].IntervalSeconds != 604800 {
				t.Fatal("raw snapshot modified")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSRunIdentityStatusKeepsManagedSourceBlockers(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name     string
		enabled  bool
		observed time.Time
		want     string
	}{
		{"disabled source", false, now, "disabled"},
		{"managed heartbeat stale", true, now.Add(-6 * time.Second), "stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			s := &Server{operations: &operationsState{db: db}}
			config := `{"source":"srun4k:one","sensor_id":"one","enabled":` + fmt.Sprint(tc.enabled) + `}`
			mock.ExpectQuery(`SELECT i.connector_id,i.config_version`).WillReturnRows(sqlmock.NewRows([]string{"connector_id", "config_version", "public_config", "encrypted_token", "endpoint_url", "certificate_pem", "state", "blocker", "observed_at", "last_success_at", "last_attempt_at", "record_count"}).AddRow("one", 1, []byte(config), []byte{}, "https://192.0.2.1", "", "healthy", "", tc.observed, tc.observed, tc.observed, 1))
			mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs("srun4k:one", "one").WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(21600))
			got, err := s.mergeManagedIdentitySources(context.Background(), []store.IdentitySourceStatus{{IdentityScope: store.IdentityScope{Source: "srun4k:one", SensorID: "one"}, ObservedAt: now.Add(-3 * time.Hour)}}, now)
			if err != nil || len(got) != 1 || got[0].State != tc.want || got[0].IntervalSeconds != 5 {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
