package controlplane

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/sharedaccess"
)

func TestMatchedSharedPolicyRecordsActionAndReportWithoutDelivery(t *testing.T) {
	previousBypass := legacyTransportTestBypass.Swap(false)
	defer legacyTransportTestBypass.Store(previousBypass)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
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
	d := sharedaccess.ObservationDecision{DecisionID: "decision-1", ExecutionID: "execution-1", PolicyID: "shared-observe", PolicyRevision: 1, AccountID: "student-1", IP: "192.0.2.8", SessionGeneration: "session-1", ObservationID: "observation-1", EvidenceVersion: "evidence-1", Result: "matched", EvaluatedAt: time.Now(), EvidenceExpiresAt: time.Now().Add(time.Hour)}
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

func TestInsufficientSharedPolicyDoesNotRecordActionOrReport(t *testing.T) {
	previousBypass := legacyTransportTestBypass.Swap(false)
	defer legacyTransportTestBypass.Store(previousBypass)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO policy_decision_records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	d := sharedaccess.ObservationDecision{DecisionID: "decision-2", PolicyID: "shared-observe", AccountID: "student-1", Result: "insufficient", EvaluatedAt: time.Now()}
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
