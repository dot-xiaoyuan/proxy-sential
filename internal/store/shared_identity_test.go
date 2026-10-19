package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
)

type sharedIdentityTestConverter struct{}

func (sharedIdentityTestConverter) ConvertValue(v any) (driver.Value, error) {
	if values, ok := v.([]string); ok {
		raw, err := json.Marshal(values)
		return raw, err
	}
	return driver.DefaultParameterConverter.ConvertValue(v)
}

func TestSharedIdentityUsesLatestCompleteBaseline(t *testing.T) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	for _, mode := range []string{"ready", "unindexed_baseline", "missing_baseline", "pending_changes"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedIdentityTestConverter{}))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			m := sharedaccess.IdentityMapping{Source: "auth", IdentitySensorID: "auth", IdentityCampusID: "campus", IdentityAccessDomain: "auth"}
			s := policy.Session{ID: "session", AccountID: "account", Status: "reconcile", IP: "192.0.2.4", Source: "auth", SensorID: "auth", CampusID: "campus", AccessDomain: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now.Add(-2 * time.Minute), HeartbeatSeconds: 60}
			s.Confirmations = []time.Time{s.ConfirmedAt}
			mock.ExpectQuery("SELECT session_data").WillReturnRows(sqlmock.NewRows([]string{"session_data"}))
			// The log lists every snapshot; only projected ones carry membership. An older unprojected
			// snapshot was superseded and is skipped, so an unprojected baseline leaves the window uncovered.
			headers := sqlmock.NewRows([]string{"snapshot_id", "observed_at", "projected"})
			if mode != "missing_baseline" {
				headers.AddRow("legacy", now.Add(-3*time.Minute), false).AddRow("baseline", s.ConfirmedAt, mode != "unindexed_baseline")
			}
			headers.AddRow("current", now.Add(-time.Second), true)
			mock.ExpectQuery("SELECT snapshot_id,observed_at,projected FROM identity_snapshot_log").WillReturnRows(headers)
			first := now.Add(-time.Second)
			if mode == "ready" || mode == "pending_changes" {
				first = s.ConfirmedAt
			}
			members := sqlmock.NewRows([]string{"confirmed_at", "document"})
			raw, _ := json.Marshal(map[string]any{"session_id": s.ID, "account_id": s.AccountID, "ip": s.IP, "session_status": "reconcile", "first_confirmed_at": first.Format(time.RFC3339Nano)})
			members.AddRow(first, raw)
			mock.ExpectQuery("SELECT p.confirmed_at,p.document FROM account_identity_session_projection").WillReturnRows(members)
			mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"pending"}).AddRow(mode == "pending_changes"))
			result, err := (&DBStore{pg: &PostgresStore{db: db}}).SharedIdentitySessions(context.Background(), m, s.IP, now.Add(-time.Minute), now, 60)
			if err != nil || len(result) == 0 {
				t.Fatalf("%+v %v", result, err)
			}
			if (result[0].IdentityIssue == "") != (mode == "ready") {
				t.Fatalf("baseline state: %+v", result)
			}
			if mode == "ready" && (result[0].State(now.Add(-time.Minute)) != "active" || result[0].State(now) != "active") {
				t.Fatalf("complete baseline did not cover observation window: %+v", result)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
