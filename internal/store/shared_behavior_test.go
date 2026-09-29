package store

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListSharedBehaviorReturnsLatestGatewayProfile(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &PostgresStore{db: db}
	observed := time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC)
	raw := `{"observation_id":"shared-behavior-latest","sensor_id":"sensor-a","ip":"192.0.2.1","status":"confirmed","confidence":95,"signal_groups":["tcp_stack","ttl_path","ua_os"],"reasons":[],"conflicts":[],"coverage_state":"verified","rule_version":"shared-behavior/v3","first_seen":"2026-09-28T10:50:00Z","last_seen":"2026-09-28T11:00:00Z","window_start":"2026-09-28T10:50:00Z","window_end":"2026-09-28T11:00:00Z","expires_at":"2026-10-28T11:00:00Z","router":{},"score_components":[],"feature_samples":{},"event_ids":[]}`
	mock.ExpectQuery(regexp.QuoteMeta("WITH latest AS (")).
		WithArgs(20, 0).
		WillReturnRows(sqlmock.NewRows([]string{"observation", "count"}).AddRow([]byte(raw), 1))
	page, err := store.ListSharedBehavior(context.Background(), SharedBehaviorQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Page.Total != 1 || page.Items[0].LastSeen != observed {
		t.Fatalf("unexpected latest gateway page: %+v", page)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGetSharedBehaviorCombinesWindowHistoryByGateway(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &PostgresStore{db: db}
	raw := `{"observation_id":"shared-behavior-current","sensor_id":"sensor-a","campus_id":"ncu","access_domain":"mirror","ip":"192.0.2.1","status":"confirmed","confidence":95,"signal_groups":["tcp_stack","ttl_path","ua_os"],"reasons":[],"conflicts":[],"coverage_state":"verified","rule_version":"shared-behavior/v3","first_seen":"2026-09-28T10:50:00Z","last_seen":"2026-09-28T11:00:00Z","window_start":"2026-09-28T10:50:00Z","window_end":"2026-09-28T11:00:00Z","expires_at":"2026-10-28T11:00:00Z","router":{},"score_components":[],"feature_samples":{},"event_ids":[]}`
	mock.ExpectQuery("SELECT observation,sensor_id,campus_id,access_domain,host\\(ip\\)").
		WithArgs("shared-behavior-current").
		WillReturnRows(sqlmock.NewRows([]string{"observation", "sensor_id", "campus_id", "access_domain", "ip"}).AddRow([]byte(raw), "sensor-a", "ncu", "mirror", "192.0.2.1"))
	mock.ExpectQuery("FROM shared_behavior_observation_history h").
		WithArgs("sensor-a", "ncu", "mirror", "192.0.2.1").
		WillReturnRows(sqlmock.NewRows([]string{"status", "confidence", "signal_groups", "coverage_state", "rule_version", "observed_at", "created_at"}).
			AddRow("confirmed", 95, []byte(`["tcp_stack","ttl_path","ua_os"]`), "verified", "shared-behavior/v3", time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC), time.Date(2026, 9, 28, 11, 0, 1, 0, time.UTC)).
			AddRow("likely", 65, []byte(`["tcp_stack","ttl_path"]`), "verified", "shared-behavior/v3", time.Date(2026, 9, 28, 10, 55, 0, 0, time.UTC), time.Date(2026, 9, 28, 10, 55, 1, 0, time.UTC)))
	detail, found, err := store.GetSharedBehavior(context.Background(), "shared-behavior-current")
	if err != nil || !found {
		t.Fatalf("detail found=%t err=%v", found, err)
	}
	if len(detail.History) != 2 || detail.History[0].Status != "confirmed" || detail.History[1].Status != "likely" {
		t.Fatalf("unexpected gateway history: %+v", detail.History)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
