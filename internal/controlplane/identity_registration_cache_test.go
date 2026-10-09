package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
)

// The cache must live for one policy read: a later read must see authority
// changes, including a removed registration or a shorter freshness interval.
func TestPolicyIdentityRegistrationReadScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sessions := []policy.Session{}
	for i := 0; i < 128; i++ {
		sessions = append(sessions, policy.Session{ID: fmt.Sprint(i), AccountID: "a", Source: "srun4k:one", SensorID: "one", IP: "192.0.2.1", StartedAt: now.Add(-5 * time.Hour), ConfirmedAt: now.Add(-4 * time.Hour), HeartbeatSeconds: 604800})
	}
	reader := policySandboxReader{sessions: sessions}
	expectManaged := func() {
		mock.ExpectQuery(`SELECT i.connector_id,i.config_version`).WillReturnRows(sqlmock.NewRows([]string{"connector_id", "config_version", "public_config", "encrypted_token", "endpoint_url", "certificate_pem", "state", "blocker", "observed_at", "last_success_at", "last_attempt_at", "record_count"}))
	}
	expectRegistration := func(interval int, failure error) {
		q := mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600 FROM srun4k_integrations WHERE source=\$1 AND sensor_id=\$2`).WithArgs("srun4k:one", "one")
		if failure != nil {
			q.WillReturnError(failure)
		} else {
			q.WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(interval))
		}
	}
	for _, tc := range []struct {
		name     string
		interval int
		failure  error
		state    string
	}{
		{"six-hour authority", 21600, nil, "active"},
		{"shortened freshness", 3600, nil, "unknown"},
		{"removed registration", 0, sql.ErrNoRows, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectManaged()
			expectRegistration(tc.interval, tc.failure)
			got, err := s.policySessions(context.Background(), reader, now)
			if err != nil || len(got) != len(sessions) {
				t.Fatalf("sessions=%d err=%v", len(got), err)
			}
			for _, row := range got {
				if row.State(now) != tc.state {
					t.Fatalf("session %s state=%s want=%s", row.ID, row.State(now), tc.state)
				}
				if tc.failure != nil && row.IdentityIssue != "unregistered_source" {
					t.Fatal("failed authority became trusted")
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if reader.sessions[0].HeartbeatSeconds != 604800 {
		t.Fatal("stored freshness mutated")
	}
}

func TestPolicyIdentityRegistrationSeparatesSensors(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	mock.ExpectQuery(`SELECT i.connector_id,i.config_version`).WillReturnRows(sqlmock.NewRows([]string{"connector_id", "config_version", "public_config", "encrypted_token", "endpoint_url", "certificate_pem", "state", "blocker", "observed_at", "last_success_at", "last_attempt_at", "record_count"}))
	now := time.Now().UTC()
	sessions := []policy.Session{}
	for _, sensor := range []string{"one", "wrong", "one", "wrong"} {
		sessions = append(sessions, policy.Session{ID: sensor, Source: "srun4k:one", SensorID: sensor, AccountID: "a", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 604800})
	}
	mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs("srun4k:one", "one").WillReturnRows(sqlmock.NewRows([]string{"interval"}).AddRow(21600))
	mock.ExpectQuery(`SELECT reconcile_interval_hours\*3600`).WithArgs("srun4k:one", "wrong").WillReturnRows(sqlmock.NewRows([]string{"interval"}))
	got, err := s.policySessions(context.Background(), policySandboxReader{sessions: sessions}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range got {
		if row.SensorID == "one" && row.State(now) != "active" {
			t.Fatal("registered sensor lost identity")
		}
		if row.SensorID == "wrong" && row.IdentityIssue != "unregistered_source" {
			t.Fatal("registration borrowed across sensors")
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
