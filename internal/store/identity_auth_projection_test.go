package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/normalized"
)

func authProjectionEvent() normalized.Event {
	return normalized.Event{Type: "identity", EventID: "login", Source: "ncu-srun4k", Timestamp: "2026-10-29T04:00:00Z", Subject: map[string]any{"entity_role": "endpoint", "endpoint_id": "mac:02:00:00:00:00:01", "account_id": "account-a", "ip": "192.0.2.1", "mac": "02:00:00:00:00:01"}, Payload: map[string]any{"session_id": "session-a", "action": "login", "os": "Android"}}
}

// Authentication must preserve device evidence, but fingerprint/profile reads
// and writes must not be prerequisites for committing the relationship.
func TestAuthenticationEndpointDoesNotSynchronouslyBuildProfiles(t *testing.T) {
	db, mock, _ := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO endpoint_entities`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (&PostgresStore{db: db}).commitAuthenticationEndpoints(context.Background(), []normalized.Event{authProjectionEvent()}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationReplayDoesNotWakeDeviceProfiles(t *testing.T) {
	db, mock, _ := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)WITH previous AS MATERIALIZED.*INSERT INTO account_sessions`).WillReturnRows(sqlmock.NewRows([]string{"session_id", "endpoint_id", "mac"}))
	mock.ExpectCommit()
	tx, _ := db.Begin()
	if err := writeAuthenticationSessionsTx(context.Background(), tx, []normalized.Event{authProjectionEvent()}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationChangedSessionInvalidatesBothDevices(t *testing.T) {
	db, mock, _ := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)WITH previous AS MATERIALIZED.*INSERT INTO account_sessions`).WillReturnRows(sqlmock.NewRows([]string{"session_id", "endpoint_id", "mac"}).AddRow("session-a", "new-device", "02:00:00:00:00:02").AddRow("session-a", "old-device", "02:00:00:00:00:01"))
	mock.ExpectRollback()
	tx, _ := db.Begin()
	got, err := upsertChangedAuthenticationSessions(context.Background(), tx, fragmentCompatibilitySessions([]normalized.Event{authProjectionEvent()}))
	if err != nil || len(got) != 2 || got[0].EndpointID != "new-device" || got[1].EndpointID != "old-device" {
		t.Fatalf("lost relationship invalidation: %+v %v", got, err)
	}
	tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationBackgroundPressureIncludesLeasedWork(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectQuery(`(?s)identity_derived_fresh_starts.*identity_derived_ready`).WillReturnRows(sqlmock.NewRows([]string{"age"}).AddRow(45.0))
	age, err := (&PostgresStore{db: db}).authenticationPendingAge(context.Background())
	if err != nil || age != 45*time.Second {
		t.Fatalf("claimed derivation lost from pressure: %v %v", age, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(authenticationPendingAgeSQL, "available_at") || strings.Contains(authenticationPendingAgeSQL, "lease_until") {
		t.Fatal("pressure must include already leased work")
	}
}

func TestAuthenticationArchiveKeepsImmutableBoundary(t *testing.T) {
	after := time.Date(2026, 10, 29, 5, 11, 29, 0, time.UTC)
	query, args := identityExportCandidateQuery("ncu", after)
	if !strings.Contains(query, "b.accepted_at >= $2") || len(args) != 2 || args[1] != after {
		t.Fatal("fresh archive can claim abandoned history")
	}
	query, args = identityExportCandidateQuery("legacy", time.Time{})
	if strings.Contains(query, "b.accepted_at >= $2") || len(args) != 1 {
		t.Fatal("unmigrated sources must keep their existing archive contract")
	}
}

func TestUnchangedSharedProfileOnlyCompletesJobAndSchedulesExpiry(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	profile := SharedDeviceProfile{ProfileID: "profile-a", EndpointID: "endpoint-a", LatestAccountID: "account-a"}
	previous, _ := json.Marshal(profile)
	profile.MaterializedAt = time.Now()
	expiry := time.Now().Add(time.Hour)
	job := sharedDeviceProfileJob{SubjectKey: "subject-a", LeaseOwner: "worker-a", DirtyGeneration: 7}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT lease_owner`).WillReturnRows(sqlmock.NewRows([]string{"current"}).AddRow(true))
	mock.ExpectQuery(`SELECT list_item`).WillReturnRows(sqlmock.NewRows([]string{"list_item"}).AddRow(previous))
	mock.ExpectExec(`UPDATE shared_device_profile_jobs SET processed_generation`).WithArgs(job.SubjectKey, job.DirtyGeneration, expiry, job.LeaseOwner).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (&DBStore{pg: &PostgresStore{db: db}}).publishSharedDeviceProfile(context.Background(), job, profile, nil, expiry); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationReplay20000UsersInBoundedBatches(t *testing.T) {
	seen := map[string]bool{}
	closed := 0
	for start := 0; start < 20000; start += 20 {
		events := make([]normalized.Event, 0, 50)
		for user := start; user < start+20; user++ {
			event := authProjectionEvent()
			event.EventID = fmt.Sprintf("event-%d", user)
			event.Subject["account_id"] = fmt.Sprintf("account-%d", user)
			event.Payload["session_id"] = fmt.Sprintf("session-%d", user)
			events = append(events, event, event)
			if user%5 == 0 {
				logout := event
				logout.Timestamp = "2026-10-29T04:01:00Z"
				logout.Payload = map[string]any{"session_id": event.Payload["session_id"], "action": "logout"}
				// Put the later observation before a replayed earlier one.
				events = append(events, logout, event)
			}
		}
		if len(events) > identityDerivedBatchMaxRecords {
			t.Fatal("replay exceeded the production event budget")
		}
		for _, session := range fragmentCompatibilitySessions(events) {
			if seen[session.SessionID] || session.AccountID != strings.Replace(session.SessionID, "session-", "account-", 1) {
				t.Fatalf("identity mixed across users: %+v", session)
			}
			seen[session.SessionID] = true
			if session.EndedAt != "" {
				closed++
			}
		}
	}
	if len(seen) != 20000 || closed != 4000 {
		t.Fatalf("lost replay results: users=%d closed=%d", len(seen), closed)
	}
}

func TestAuthenticationLostLeaseRollsBackResultAndInvalidation(t *testing.T) {
	db, mock, _ := sqlmock.New(sqlmock.ValueConverterOption(passthroughConverter{}))
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO endpoint_entities`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)WITH previous AS MATERIALIZED`).WillReturnRows(sqlmock.NewRows([]string{"session_id", "endpoint_id", "mac"}).AddRow("session-a", "endpoint-a", "02:00:00:00:00:01"))
	mock.ExpectExec(`(?s)INSERT INTO shared_device_profile_jobs`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE identity_ingest_fragments SET derived_state='completed'`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	s := &DBStore{pg: &PostgresStore{db: db, identityDerivedAfter: time.Now().Add(-time.Hour)}, identitySkipHistory: true}
	err := s.applyIdentityDerivedFragments(context.Background(), []identityExportFragment{{BatchID: "batch", First: 0, DerivedLeaseEpoch: 9}}, []normalized.Event{authProjectionEvent()})
	if !errors.Is(err, ErrIdentityLeaseExpired) {
		t.Fatalf("lost lease did not fence result commit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDepartedDeviceDoesNotKeepAnUnsupportedAccount(t *testing.T) {
	at := time.Now()
	profile := SharedDeviceProfile{LatestAccountID: "old-account", LatestAccountAt: &at, LatestAccountActive: true, LatestAccountMatchBasis: "exact_endpoint", AccountConflict: true}
	got := applySharedProfileAccount(profile, sharedProfileAccount{})
	if got.LatestAccountID != "" || got.LatestAccountAt != nil || got.LatestAccountActive || got.LatestAccountMatchBasis != "" || got.AccountConflict || len(got.AuthBindings) != 0 {
		t.Fatalf("departed device retained unsupported association: %+v", got)
	}
}
