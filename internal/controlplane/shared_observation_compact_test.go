package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"proxy-sentinel/internal/sharedaccess"
)

func TestPersistSharedObservationDecisionCompactModeSkipsInsufficientPolicyRow(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_COMPACT_POLICY_DECISIONS", "true")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO shared_decision_trend_buckets").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	decision := &sharedaccess.ObservationDecision{
		DecisionID:  "dec-insufficient-1",
		Result:      "insufficient",
		EvaluatedAt: time.Date(2026, 11, 27, 5, 30, 12, 0, time.UTC),
	}
	if err := persistSharedObservationDecision(context.Background(), tx, decision); err != nil {
		t.Fatalf("persist compact insufficient: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
