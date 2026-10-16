package controlplane

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

type sharedReplayReader struct {
	store.Reader
	window   sharedaccess.Window
	item     sharedaccess.BehaviorAssessment
	sessions []policy.Session
}

func (r sharedReplayReader) ReadSharedObservation(context.Context, store.SharedObservationScope, sharedaccess.Config, time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error) {
	return r.window, r.item, nil
}
func (r sharedReplayReader) SharedIdentitySessions(context.Context, sharedaccess.IdentityMapping, string, time.Time, time.Time, int) ([]policy.Session, error) {
	return r.sessions, nil
}

func TestSharedObservationCommitsOnlyRecordsAndRetriesFailedTransaction(t *testing.T) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	cfg := sharedaccess.Config{Version: "v1", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture", Source: "packet-sidecar"}}, IdentityMappings: []sharedaccess.IdentityMapping{{SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture", Source: "auth", IdentitySensorID: "auth", IdentityCampusID: "ncu", IdentityAccessDomain: "auth", ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}}}
	w := sharedaccess.Window{ID: "evidence-v1", RuleVersion: sharedaccess.RuleVersion, SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture", IP: "192.0.2.4", From: now.Add(-time.Minute), To: now.Add(-time.Second), LastObservedAt: now.Add(-time.Second), Sources: []string{"packet-sidecar"}, Records: []sharedaccess.RecordRef{{EventID: "raw", Source: "packet-sidecar", InstanceID: "one"}}, EventIDs: []string{"raw"}, Complete: true, CoverageVerified: true, AssociatedClients: []string{"a", "b"}, StrongAnchor: "ieee1905_association", DeviceLowerBound: 2}
	item, _ := sharedaccess.AssessBehavior(w.ID, "", w, sharedaccess.BehaviorRouterContext{})
	item.Current = true
	sessions := []policy.Session{{ID: "session", AccountID: "alice", IP: w.IP, Source: "auth", SensorID: "auth", CampusID: "ncu", AccessDomain: "auth", StartedAt: now.Add(-time.Hour), ConfirmedAt: now.Add(-time.Second), Confirmations: []time.Time{now.Add(-2 * time.Minute), now.Add(-time.Second)}, HeartbeatSeconds: 60}}
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{readOnly: true, sharedObservationEnabled: true, sharedConfig: cfg, operations: &operationsState{db: db}, reader: sharedReplayReader{window: w, item: item, sessions: sessions}, identitySources: []identitySourceRegistration{{IdentityScope: store.IdentityScope{Source: "auth", SensorID: "auth", CampusID: "ncu", AccessDomain: "auth"}, IntervalSeconds: 60}}}
	for _, fail := range []bool{true, false, false} {
		mock.ExpectBegin()
		mock.ExpectQuery("SELECT job_id").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "ip", "revision", "last"}).AddRow("job", "mirror", "ncu", "capture", w.IP, 1, nil))
		mock.ExpectExec("UPDATE shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("INSERT INTO shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
		expectation := mock.ExpectExec("INSERT INTO policy_decision_records")
		if fail {
			expectation.WillReturnError(errors.New("database unavailable"))
			mock.ExpectRollback()
			mock.ExpectExec("UPDATE shared_observation_jobs SET attempts").WillReturnResult(sqlmock.NewResult(0, 1))
		} else {
			expectation.WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec("UPDATE shared_observation_jobs SET completed_revision").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
		}
		did, e := s.processSharedObservation(context.Background(), now)
		if !did || (e != nil) != fail {
			t.Fatalf("did=%v err=%v", did, e)
		}
		if err = mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
	result := sharedaccess.EvaluateObservation(w, cfg, sessions, now)
	a := sharedaccess.NewObservationDecision(w, result, cfg, now)
	b := sharedaccess.NewObservationDecision(w, result, cfg, now.Add(time.Second))
	if a.Result != "insufficient" || a.ExecutionID != "" || a.Violated || a.DecisionID != b.DecisionID || a.Mode != "observe" || a.DeliveryStatus != "not_sent" || a.PlannedAction != "disconnect" {
		raw, _ := json.Marshal(a)
		t.Fatal(string(raw))
	}
	w.ID = "evidence-v2"
	c := sharedaccess.NewObservationDecision(w, result, cfg, now)
	if c.DecisionID == a.DecisionID {
		t.Fatal("new evidence lost")
	}
	expired := sharedaccess.NewObservationDecision(w, result, cfg, now.Add(4*time.Minute))
	if expired.Result != "expired" || expired.Violated || expired.ExecutionID != "" {
		t.Fatal("stale evidence triggered")
	}
	// Any attempt to write actions, notifications, outbox, or call unrelated DB
	// code fails the strict SQL expectations above; the reader has no controller.
}

type sharedTestConverter struct{}

func (sharedTestConverter) ConvertValue(v any) (driver.Value, error) {
	if values, ok := v.([]string); ok {
		b, e := json.Marshal(values)
		return b, e
	}
	return driver.DefaultParameterConverter.ConvertValue(v)
}
