package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSharedActionReviewKeepsLegacyActionAndShowsCorrection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	actions := map[string]EnforcementAction{
		"legacy": {ActionID: "legacy", Mode: "record_only", CreatedBy: "shared_observation",
			PolicyParameters: PolicyActionParameters{DecisionID: "old-decision"}},
	}
	mock.ExpectQuery("SELECT decision_id,classification,reason FROM shared_observation_decision_corrections").WillReturnRows(
		sqlmock.NewRows([]string{"decision_id", "classification", "reason"}).
			AddRow("old-decision", "insufficient_evidence", "strong_anchor_missing"))
	if err := annotateSharedActionReview(context.Background(), db, actions); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions["legacy"].EvidenceReviewStatus != "insufficient_evidence" || actions["legacy"].EvidenceReviewReason != "strong_anchor_missing" {
		t.Fatalf("legacy action not preserved with correction: %+v", actions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedDecisionReviewDoesNotConfirmMissingEvidence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT decision_id,classification,reason FROM shared_observation_decision_corrections").WillReturnRows(
		sqlmock.NewRows([]string{"decision_id", "classification", "reason"}).
			AddRow("old-decision", "unverified", "saved_evidence_unavailable"))
	items, err := annotateSharedDecisionReview(context.Background(), db, []string{"old-decision"},
		[]json.RawMessage{json.RawMessage(`{"trigger":"shared_access","result":"matched","execution_id":"shared-observe-old"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(items[0], &got); err != nil {
		t.Fatal(err)
	}
	if got["evidence_review_status"] != "unverified" || got["evidence_review_reason"] != "saved_evidence_unavailable" || got["result"] != "matched" {
		t.Fatalf("original decision or review status changed unexpectedly: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyHistoricalSharedDecisionOnlyUsesSavedEvidence(t *testing.T) {
	cases := []struct {
		name, body, want, reason string
	}{
		{"missing", `{}`, "unverified", "saved_evidence_unavailable"},
		{"empty evidence object", `{"result":"matched","evidence":{}}`, "unverified", "saved_evidence_unavailable"},
		{"old weak anchor", `{"result":"matched","evidence":{"id":"old","event_ids":["event-1"],"complete":true,"coverage_verified":true,"device_lower_bound":2}}`, "insufficient_evidence", "strong_anchor_missing"},
		{"old weak bound", `{"result":"matched","evidence":{"id":"old","event_ids":["event-1"],"complete":true,"coverage_verified":true,"strong_anchor":"ieee1905_association","device_lower_bound":1}}`, "insufficient_evidence", "device_lower_bound_below_two"},
		{"strong snapshot", `{"result":"matched","evidence":{"id":"strong","event_ids":["event-2"],"complete":true,"coverage_verified":true,"strong_anchor":"ieee1905_association","device_lower_bound":2}}`, "", ""},
		{"unreadable", `{"result":`, "unverified", "saved_evidence_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := classifyHistoricalSharedDecision(json.RawMessage(tc.body))
			if got != tc.want || reason != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", got, reason, tc.want, tc.reason)
			}
		})
	}
}

func TestHistoricalSharedCorrectionBatchIsBoundedAndAudited(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Date(2026, 11, 10, 8, 53, 0, 0, time.UTC)
	snapshot := cutoff.Add(time.Hour)
	start := time.Unix(0, 0).UTC()
	weak := `{"result":"matched","evidence":{"id":"old","event_ids":["event-1"],"complete":true,"coverage_verified":true,"device_lower_bound":1}}`
	strong := `{"result":"matched","evidence":{"id":"strong","event_ids":["event-2"],"complete":true,"coverage_verified":true,"strong_anchor":"ieee1905_association","device_lower_bound":2}}`
	weakHash := sha256.Sum256([]byte(weak))
	mock.ExpectBegin()
	mock.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO shared_observation_correction_runs").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT bad_rule_before,received_before,cursor_evaluated_at").WillReturnRows(
		sqlmock.NewRows([]string{"bad_rule_before", "received_before", "cursor_evaluated_at", "cursor_decision_id", "status"}).
			AddRow(cutoff, snapshot, start, "", "running"))
	mock.ExpectQuery("SELECT decision_id,evaluated_at,evidence_version,document").WillReturnRows(
		sqlmock.NewRows([]string{"decision_id", "evaluated_at", "evidence_version", "document"}).
			AddRow("weak", cutoff.Add(-2*time.Minute), "v1", []byte(weak)).
			AddRow("strong", cutoff.Add(-time.Minute), "v2", []byte(strong)))
	mock.ExpectQuery("INSERT INTO shared_observation_decision_corrections").WillReturnRows(
		sqlmock.NewRows([]string{"source_sha256", "classification", "reason"}).
			AddRow(hex.EncodeToString(weakHash[:]), "insufficient_evidence", "strong_anchor_missing"))
	mock.ExpectExec("UPDATE shared_observation_correction_runs SET").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	result, err := ReviewHistoricalSharedDecisionBatch(context.Background(), db, "review-1", cutoff, snapshot, 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Inspected != 2 || result.Insufficient != 1 || result.Unverified != 0 || !result.Completed || result.NextDecisionID != "strong" {
		t.Fatalf("unexpected batch result: %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
