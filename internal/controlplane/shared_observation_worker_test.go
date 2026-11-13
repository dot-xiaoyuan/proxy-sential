package controlplane

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type sharedReplayReader struct {
	store.Reader
	window   sharedaccess.Window
	item     sharedaccess.BehaviorAssessment
	sessions []policy.Session
}

type expiredSharedReader struct{ sharedReplayReader }

func TestSharedObservationExpiryBorrowRequiresIdleAsyncRealtimeWorker(t *testing.T) {
	tests := []struct {
		name     string
		lane     string
		async    bool
		did      bool
		err      error
		expected bool
	}{
		{name: "idle async realtime worker borrows", lane: "realtime_new", async: true, expected: true},
		{name: "busy realtime worker keeps its task", lane: "realtime_new", async: true, did: true},
		{name: "failed realtime claim does not borrow", lane: "realtime_new", async: true, err: errors.New("claim failed")},
		{name: "legacy realtime worker does not borrow", lane: "realtime_new", async: false},
		{name: "reserved expiry worker does not borrow", lane: "expiry", async: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldBorrowSharedObservationExpiry(tt.lane, tt.async, tt.did, tt.err); got != tt.expected {
				t.Fatalf("shouldBorrowSharedObservationExpiry() = %v, want %v", got, tt.expected)
			}
		})
	}
	if !sharedObservationExpiryLane("expiry_borrowed") || sharedObservationNewDependency("expiry_borrowed", true) {
		t.Fatal("borrowed expiry processing must keep expiry and latency classification")
	}
	if group, _ := sharedObservationClaimOrder("expiry_borrowed"); group != "expiry" {
		t.Fatalf("borrowed worker claim group = %q, want expiry", group)
	}
}

func TestSharedObservationLegacyExpiryWorkerBorrowsOldRealtimeOnlyWhenIdle(t *testing.T) {
	tests := []struct {
		name     string
		lane     string
		mode     string
		did      bool
		err      error
		expected bool
	}{
		{name: "idle legacy expiry worker borrows old realtime", lane: "expiry", mode: "legacy", expected: true},
		{name: "idle shadow expiry worker borrows old realtime", lane: "expiry", mode: "shadow", expected: true},
		{name: "expiry work takes priority", lane: "expiry", mode: "legacy", did: true},
		{name: "failed expiry claim does not borrow", lane: "expiry", mode: "legacy", err: errors.New("claim failed")},
		{name: "async expiry worker remains reserved", lane: "expiry", mode: "async"},
		{name: "realtime worker does not borrow old lane", lane: "realtime_new", mode: "legacy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldBorrowSharedObservationOld(tt.lane, tt.mode, tt.did, tt.err); got != tt.expected {
				t.Fatalf("shouldBorrowSharedObservationOld() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func (expiredSharedReader) ReadSharedObservation(context.Context, store.SharedObservationScope, sharedaccess.Config, time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error) {
	panic("expired evidence with a stored document must not query ClickHouse")
}

func (r sharedReplayReader) ReadSharedObservation(context.Context, store.SharedObservationScope, sharedaccess.Config, time.Time) (sharedaccess.Window, sharedaccess.BehaviorAssessment, error) {
	return r.window, r.item, nil
}
func (r sharedReplayReader) SharedIdentitySessions(context.Context, sharedaccess.IdentityMapping, string, time.Time, time.Time, int) ([]policy.Session, error) {
	return r.sessions, nil
}

func TestSharedObservationCommitsOnlyRecordsAndRetriesFailedTransaction(t *testing.T) {
	previousBypass := legacyTransportTestBypass.Swap(false)
	defer legacyTransportTestBypass.Store(previousBypass)
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
	previousToken := newSharedObservationLeaseToken
	newSharedObservationLeaseToken = func() (string, error) { return "test-lease", nil }
	defer func() { newSharedObservationLeaseToken = previousToken }()
	for attempt, fail := range []bool{true, false, false} {
		retiredRows, upsertedRows := int64(0), int64(1)
		if attempt == 1 { // Retiring the previous current row still wakes the profile.
			retiredRows, upsertedRows = 1, 0
		} else if attempt == 2 { // Unchanged observation leaves the profile alone.
			upsertedRows = 0
		}
		// The singleton mode row must stay unlocked so concurrent workers can claim separate jobs.
		mock.ExpectBegin()
		mock.ExpectExec("SET LOCAL synchronous_commit = off").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("FOR UPDATE OF j SKIP LOCKED").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "ip", "revision", "last", "dependency", "new_dependency", "generation"}).AddRow("job", "mirror", "ncu", "capture", w.IP, 1, nil, now, true, ""))
		mock.ExpectCommit()
		mock.ExpectBegin()
		mock.ExpectExec("SET LOCAL synchronous_commit = on").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("UPDATE shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, retiredRows))
		mock.ExpectExec("(?s)INSERT INTO shared_behavior_observations.*IS DISTINCT FROM").WillReturnResult(sqlmock.NewResult(0, upsertedRows))
		if retiredRows+upsertedRows > 0 {
			mock.ExpectExec("INSERT INTO shared_device_profile_jobs").WillReturnResult(sqlmock.NewResult(0, 1))
		}
		mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT e.execution_id FROM shared_observation_episode_index").WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT e.execution_id FROM shared_observation_episode_index").WillReturnError(sql.ErrNoRows)
		mock.ExpectExec("INSERT INTO shared_observation_executions").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("INSERT INTO shared_observation_episode_index").WillReturnResult(sqlmock.NewResult(0, 1))
		expectation := mock.ExpectExec("INSERT INTO policy_decision_records")
		if fail {
			expectation.WillReturnError(errors.New("database unavailable"))
			mock.ExpectRollback()
			mock.ExpectExec("UPDATE shared_observation_jobs SET attempts").WillReturnResult(sqlmock.NewResult(0, 1))
		} else {
			expectation.WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec("INSERT INTO enforcement_actions").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec("INSERT INTO behavior_report_outbox").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery("SELECT mode FROM shared_observation_wake_mode").WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("async"))
			mock.ExpectQuery("SELECT revision,lease_token").WillReturnRows(sqlmock.NewRows([]string{"revision", "lease_token", "generation_id", "canceled_epoch"}).AddRow(1, "test-lease", "", ""))
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
	if a.Result != "matched" || a.ExecutionID == "" || !a.Violated || a.DecisionID != b.DecisionID || a.Mode != "manual" || a.DeliveryStatus != "record_only" || a.PlannedAction != "disconnect" {
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
	// Strict SQL expectations ensure matched decisions write terminal records
	// without delivery attempts or controller calls.
}

func TestSharedObservationNewRevisionRejectsOldResult(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldToken := newSharedObservationLeaseToken
	newSharedObservationLeaseToken = func() (string, error) { return "old-lease", nil }
	defer func() { newSharedObservationLeaseToken = oldToken }()
	s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture"}}}, operations: &operationsState{db: db}, reader: sharedReplayReader{}}
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL synchronous_commit = off").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("j.revision>j.completed_revision").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "ip", "revision", "last", "dependency", "new_dependency", "generation"}).AddRow("job", "mirror", "ncu", "capture", "192.0.2.4", 1, nil, now, true, ""))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL synchronous_commit = on").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_device_profile_jobs").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE shared_observation_executions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO policy_decision_records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT mode FROM shared_observation_wake_mode").WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("async"))
	mock.ExpectQuery("SELECT revision,lease_token").WillReturnRows(sqlmock.NewRows([]string{"revision", "lease_token", "generation_id", "canceled_epoch"}).AddRow(2, "new-lease", "", ""))
	mock.ExpectRollback()
	did, err := s.processSharedObservation(context.Background(), now)
	if err != nil || !did {
		t.Fatalf("did=%v err=%v", did, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedObservationClaimLanes(t *testing.T) {
	for _, tt := range []struct{ lane, group, order string }{
		{"realtime_new", "realtime", "CASE WHEN last_dependency_at>=now()-interval '5 minutes' THEN 0 ELSE 1 END,last_dependency_at,job_id"},
		{"realtime_old", "realtime_old", "dirty_since,job_id"},
		{"expiry", "expiry", "next_attempt_at,dirty_since,job_id"},
	} {
		group, order := sharedObservationClaimOrder(tt.lane)
		if group != tt.group || order != tt.order {
			t.Fatalf("%s: group=%s order=%s", tt.lane, group, order)
		}
	}
	if predicate := sharedObservationClaimPredicate("realtime_old"); predicate != "$3='realtime_old' AND j.revision>j.completed_revision" {
		t.Fatalf("old lane must use an indexable pending-only predicate: %s", predicate)
	}
	if predicate := sharedObservationClaimPredicate("realtime_new"); !strings.Contains(predicate, "j.revision>j.completed_revision OR") {
		t.Fatalf("new lane must retain legacy due rechecks: %s", predicate)
	}
	lanes := map[string]int{}
	for i := 0; i < 8; i++ {
		lanes[sharedObservationWorkerLane(i)]++
	}
	if lanes["realtime_new"] != 7 || lanes["realtime_old"] != 0 || lanes["expiry"] != 1 || sharedObservationWorkerLane(0) != "realtime_new" || sharedObservationWorkerLane(1) != "expiry" {
		t.Fatalf("unexpected worker lanes: %+v", lanes)
	}
	if !sharedObservationNewDependency("realtime_new", true) || sharedObservationNewDependency("realtime_new", false) || sharedObservationNewDependency("expiry", true) {
		t.Fatal("natural expiry or gap recheck counted as a new dependency")
	}
}

func TestSharedObservationClaimBindsEveryPostgresPlaceholder(t *testing.T) {
	placeholder := regexp.MustCompile(`\$([1-9][0-9]*)`)
	for _, lane := range []string{"realtime_new", "realtime_old", "expiry", "expiry_borrowed"} {
		t.Run(lane, func(t *testing.T) {
			query, args := sharedObservationClaimQuery(lane, []byte(`[]`), 180, "lease-token")
			used := make(map[int]bool)
			for _, match := range placeholder.FindAllStringSubmatch(query, -1) {
				index, err := strconv.Atoi(match[1])
				if err != nil || index > len(args) {
					t.Fatalf("placeholder %q has no argument: %v", match[0], err)
				}
				used[index] = true
			}
			for index := range args {
				if !used[index+1] {
					t.Fatalf("argument %d is unused by claim SQL", index+1)
				}
			}
			if lane == "realtime_old" {
				if len(args) != 3 || args[1] != "lease-token" || args[2] != "realtime_old" || !strings.Contains(query, "lease_token=$2") {
					t.Fatalf("old lane bindings changed: args=%v", args)
				}
			} else if len(args) != 4 || args[1] != 180 || args[2] != "lease-token" || !strings.Contains(query, "lease_token=$3") {
				t.Fatalf("lane %s bindings changed: args=%v", lane, args)
			}
		})
	}
}

func TestSharedObservationLegacyOldWorkerGate(t *testing.T) {
	for _, tt := range []struct {
		index   int
		mode    string
		flag    bool
		enabled bool
		lane    string
	}{
		{0, "legacy", false, true, "realtime_new"},
		{1, "legacy", false, true, "expiry"},
		{2, "legacy", false, false, "realtime_new"},
		{2, "legacy", true, true, "realtime_old"},
		{2, "shadow", true, false, "realtime_new"},
		{2, "async", true, true, "realtime_new"},
		{3, "legacy", true, false, "realtime_new"},
	} {
		if got := sharedObservationWorkerEnabled(tt.index, tt.mode, tt.flag, 8); got != tt.enabled {
			t.Fatalf("index=%d mode=%s flag=%t enabled=%t, want %t", tt.index, tt.mode, tt.flag, got, tt.enabled)
		}
		if got := sharedObservationWorkerLaneForMode(tt.index, tt.mode, tt.flag); got != tt.lane {
			t.Fatalf("index=%d mode=%s flag=%t lane=%s, want %s", tt.index, tt.mode, tt.flag, got, tt.lane)
		}
	}
}

func TestSharedObservationAsyncWorkerLimitKeepsExpiryLane(t *testing.T) {
	for _, tt := range []struct {
		configured string
		want       int
		valid      bool
	}{
		{"", 8, true}, {" 3 ", 3, true}, {"2", 2, true}, {"8", 8, true},
		{"1", 0, false}, {"9", 0, false}, {"invalid", 0, false},
	} {
		workers, err := parseSharedObservationAsyncWorkers(tt.configured)
		if workers != tt.want || (err == nil) != tt.valid {
			t.Fatalf("configured=%q workers=%d err=%v, want workers=%d valid=%t", tt.configured, workers, err, tt.want, tt.valid)
		}
	}
	for limit := 2; limit <= 8; limit++ {
		count := 0
		for index := 0; index < 8; index++ {
			enabled := sharedObservationWorkerEnabled(index, "async", false, limit)
			if enabled {
				count++
			}
			if index == 1 && (!enabled || sharedObservationWorkerLaneForMode(index, "async", false) != "expiry") {
				t.Fatalf("limit=%d: expiry lane must stay reserved", limit)
			}
			if index >= limit && enabled {
				t.Fatalf("limit=%d index=%d unexpectedly enabled", limit, index)
			}
		}
		if count != limit {
			t.Fatalf("limit=%d enabled=%d", limit, count)
		}
	}
	if sharedObservationWorkerEnabled(2, "legacy", false, 8) || sharedObservationWorkerEnabled(2, "shadow", false, 8) || !sharedObservationWorkerEnabled(2, "legacy", true, 2) {
		t.Fatal("async cap changed legacy or shadow worker semantics")
	}
}

func TestSharedObservationExpiryUsesStoredEvidence(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	w := sharedaccess.Window{ID: "old-evidence", RuleVersion: sharedaccess.RuleVersion, SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture", IP: "192.0.2.4", From: now.Add(-6 * time.Minute), To: now.Add(-5 * time.Minute), LastObservedAt: now.Add(-5 * time.Minute)}
	item := sharedaccess.BehaviorAssessment{ObservationID: w.ID, SensorID: w.SensorID, CampusID: w.CampusID, AccessDomain: w.AccessDomain, IP: w.IP, Current: true}
	previous, _ := json.Marshal(sharedObservationDocument{Window: w, Assessment: item, Result: sharedaccess.Result{State: "insufficient"}})
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldToken := newSharedObservationLeaseToken
	newSharedObservationLeaseToken = func() (string, error) { return "expiry-lease", nil }
	defer func() { newSharedObservationLeaseToken = oldToken }()
	s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture"}}}, operations: &operationsState{db: db}, reader: expiredSharedReader{}}
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL synchronous_commit = off").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("(?s)j.revision=j.completed_revision.*m.mode='async'").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "ip", "revision", "last", "dependency", "new_dependency", "generation"}).AddRow("job", "mirror", "ncu", "capture", w.IP, 1, previous, now.Add(-5*time.Minute), false, ""))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL synchronous_commit = on").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_device_profile_jobs").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE shared_observation_executions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO policy_decision_records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT mode FROM shared_observation_wake_mode").WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("async"))
	mock.ExpectQuery("SELECT revision,lease_token").WillReturnRows(sqlmock.NewRows([]string{"revision", "lease_token", "generation_id", "canceled_epoch"}).AddRow(1, "expiry-lease", "", ""))
	mock.ExpectExec("UPDATE shared_observation_jobs SET completed_revision").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	did, err := s.processSharedObservationWithLimit(context.Background(), now, nil, "expiry")
	if err != nil || !did {
		t.Fatalf("did=%v err=%v", did, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedObservationFreshExpiryReschedulesWithoutRetiringEvidence(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	w := sharedaccess.Window{ID: "fresh-evidence", RuleVersion: sharedaccess.RuleVersion, SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture", IP: "192.0.2.4", LastObservedAt: now.Add(-time.Minute)}
	item := sharedaccess.BehaviorAssessment{ObservationID: w.ID, SensorID: w.SensorID, CampusID: w.CampusID, AccessDomain: w.AccessDomain, IP: w.IP, Current: true}
	previous, _ := json.Marshal(sharedObservationDocument{Window: w, Assessment: item, Result: sharedaccess.Result{State: "basis_present"}})
	for _, tt := range []struct {
		lane        string
		rescheduled int64
	}{
		{lane: "expiry", rescheduled: 1},
		{lane: "expiry_borrowed", rescheduled: 0}, // A concurrent wake replaced this lease.
	} {
		t.Run(tt.lane, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			oldToken := newSharedObservationLeaseToken
			newSharedObservationLeaseToken = func() (string, error) { return "expiry-lease", nil }
			defer func() { newSharedObservationLeaseToken = oldToken }()
			s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture"}}}, operations: &operationsState{db: db}, reader: expiredSharedReader{}}
			mock.ExpectBegin()
			mock.ExpectExec("SET LOCAL synchronous_commit = off").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("j.revision=j.completed_revision").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "ip", "revision", "last", "dependency", "new_dependency", "generation"}).AddRow("job", "mirror", "ncu", "capture", w.IP, 1, previous, now.Add(-time.Minute), false, ""))
			mock.ExpectCommit()
			mock.ExpectExec(`(?s)UPDATE shared_observation_jobs SET next_attempt_at=.*lease_token=\$2 AND revision=\$3 AND completed_revision=\$3 AND generation_id=\$4 AND canceled_epoch='' AND NOT expired`).WithArgs("job", "expiry-lease", int64(1), "", w.LastObservedAt.Add(180*time.Second)).WillReturnResult(sqlmock.NewResult(0, tt.rescheduled))
			did, err := s.processSharedObservationWithLimit(context.Background(), now, nil, tt.lane)
			if err != nil || !did {
				t.Fatalf("did=%v err=%v", did, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type sharedTestConverter struct{}

func (sharedTestConverter) ConvertValue(v any) (driver.Value, error) {
	if values, ok := v.([]string); ok {
		b, e := json.Marshal(values)
		return b, e
	}
	return driver.DefaultParameterConverter.ConvertValue(v)
}
func TestSharedObservationLostLeaseRejectsSameRevision(t *testing.T) {
	now := time.Date(2026, 10, 21, 1, 0, 0, 0, time.UTC)
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	oldToken := newSharedObservationLeaseToken
	newSharedObservationLeaseToken = func() (string, error) { return "old-lease", nil }
	defer func() { newSharedObservationLeaseToken = oldToken }()
	s := &Server{sharedConfig: sharedaccess.Config{FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "mirror", CampusID: "ncu", AccessDomain: "capture"}}}, operations: &operationsState{db: db}, reader: sharedReplayReader{}}
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL synchronous_commit = off").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("j.revision>j.completed_revision").WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "ip", "revision", "last", "dependency", "new_dependency", "generation"}).AddRow("job", "mirror", "ncu", "capture", "192.0.2.4", 1, nil, now, true, ""))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL synchronous_commit = on").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_behavior_observations").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_device_profile_jobs").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE shared_observation_executions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO policy_decision_records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT mode FROM shared_observation_wake_mode").WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("async"))
	mock.ExpectQuery("SELECT revision,lease_token").WillReturnRows(sqlmock.NewRows([]string{"revision", "lease_token", "generation_id", "canceled_epoch"}).AddRow(1, "replacement-lease", "", ""))
	mock.ExpectRollback()
	did, err := s.processSharedObservation(context.Background(), now)
	if err != nil || !did {
		t.Fatalf("did=%v err=%v", did, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedObservationClaimMustCommitBeforeReadingEvidence(t *testing.T) {
	for _, empty := range []bool{true, false} {
		db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedTestConverter{}))
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{sharedConfig: sharedaccess.Config{}, operations: &operationsState{db: db}, reader: expiredSharedReader{}}
		mock.ExpectBegin()
		mock.ExpectExec("SET LOCAL synchronous_commit = off").WillReturnResult(sqlmock.NewResult(0, 0))
		q := mock.ExpectQuery("FOR UPDATE OF j SKIP LOCKED")
		if empty {
			q.WillReturnError(sql.ErrNoRows)
			mock.ExpectRollback()
		} else {
			q.WillReturnRows(sqlmock.NewRows([]string{"id", "sensor", "campus", "domain", "ip", "revision", "last", "dependency", "new_dependency", "generation"}).AddRow("job", "mirror", "ncu", "capture", "192.0.2.4", 1, nil, time.Now(), true, ""))
			mock.ExpectCommit().WillReturnError(errors.New("claim commit lost"))
		}
		did, err := s.processSharedObservation(context.Background(), time.Now())
		if did || (err != nil) == empty {
			t.Fatalf("empty=%t did=%t err=%v", empty, did, err)
		}
		if err = mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}
