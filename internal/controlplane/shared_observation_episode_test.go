package controlplane

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
)

func matchedEpisodeDecision(id, version string, at time.Time) sharedaccess.ObservationDecision {
	return sharedaccess.ObservationDecision{
		DecisionID: id, PolicyID: sharedaccess.ObservationPolicyID, PolicyRevision: 3,
		AccountID: "student-1", IP: "192.0.2.8", CampusID: "campus", AccessDomain: "domain",
		SessionGeneration: "session-generation", ObservationID: "observation-1", EvidenceVersion: version,
		Result: "matched", EvaluatedAt: at, EvidenceExpiresAt: at.Add(10 * time.Minute), CooldownSeconds: 600,
		Evidence: sharedaccess.Window{SensorID: "sensor-1"},
	}
}

func TestSharedEpisodeScopeIgnoresEvidenceRevision(t *testing.T) {
	at := time.Now().UTC()
	first := matchedEpisodeDecision("decision-1", "evidence-1", at)
	next := matchedEpisodeDecision("decision-2", "evidence-2", at.Add(time.Minute))
	if sharedObservationEpisodeScope(first) != sharedObservationEpisodeScope(next) {
		t.Fatal("evidence revision changed the episode scope")
	}
	next.SessionGeneration = "new-session"
	if sharedObservationEpisodeScope(first) == sharedObservationEpisodeScope(next) {
		t.Fatal("new authentication generation reused the prior episode")
	}
}

func TestSharedEpisodeClosesOnlyOnExplicitSessionEnd(t *testing.T) {
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	previous := []sharedEpisodeSessionRef{{ID: "session-1", Source: "ncu", StartedAt: started}}
	at := started.Add(time.Hour)
	if sharedObservationEpisodeSessionsEnded(previous, nil, at) {
		t.Fatal("missing identity evidence was treated as an ended session")
	}
	current := []policy.Session{{ID: "session-1", Source: "ncu", StartedAt: started, EndedAt: at}}
	if !sharedObservationEpisodeSessionsEnded(previous, current, at) {
		t.Fatal("explicit session end did not close the episode")
	}
	current[0].StartedAt = started.Add(time.Minute)
	if sharedObservationEpisodeSessionsEnded(previous, current, at) {
		t.Fatal("another session generation closed the episode")
	}
}

func TestMatchedSharedEpisodeContinuationOnlyAppendsDecision(t *testing.T) {
	previousBypass := legacyTransportTestBypass.Swap(false)
	defer legacyTransportTestBypass.Store(previousBypass)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	d := matchedEpisodeDecision("decision-2", "evidence-2", at)
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT e.execution_id FROM shared_observation_episode_index").WillReturnRows(sqlmock.NewRows([]string{"execution_id"}).AddRow("existing-episode"))
	mock.ExpectExec("UPDATE shared_observation_executions SET evidence_version").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO policy_decision_records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSharedObservationDecision(context.Background(), tx, d); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMatchedSharedEpisodeFirstDecisionCreatesOneAction(t *testing.T) {
	previousBypass := legacyTransportTestBypass.Swap(false)
	defer legacyTransportTestBypass.Store(previousBypass)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	d := matchedEpisodeDecision("decision-1", "evidence-1", time.Now().UTC())
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT e.execution_id FROM shared_observation_episode_index").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT e.execution_id FROM shared_observation_episode_index").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO shared_observation_executions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_observation_episode_index").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO policy_decision_records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO enforcement_actions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO behavior_report_outbox").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistSharedObservationDecision(context.Background(), tx, d); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedEpisodeRestartWithSameEvidenceGetsNewExecutionID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	d := matchedEpisodeDecision("same-decision", "same-evidence", time.Now().UTC())
	firstID := "shared-observe-episode-" + policy.StableID(sharedObservationEpisodeScope(d), d.DecisionID, "")
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT e.execution_id FROM shared_observation_episode_index").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("SELECT e.execution_id FROM shared_observation_episode_index").WillReturnRows(
		sqlmock.NewRows([]string{"execution_id"}).AddRow(firstID))
	mock.ExpectExec("INSERT INTO shared_observation_executions").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO shared_observation_episode_index").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	created, err := ensureSharedObservationEpisode(context.Background(), tx, &d)
	if err != nil {
		t.Fatal(err)
	}
	if !created || d.ExecutionID == firstID {
		t.Fatalf("new episode reused the previous ID: created=%t execution=%s", created, d.ExecutionID)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
