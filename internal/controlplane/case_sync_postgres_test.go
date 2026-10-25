package controlplane

import (
	"context"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestPostgresSharedCaseLifecycle(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, r, assessment := caseSyncFixture()
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	s.operations = state
	if err = s.syncCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	caseID := proxyReviewCaseForSharedAssessment(assessment).CaseID
	if got := state.doc.Cases[caseID]; got.RiskKind != "shared_access" || got.EvidenceSnapshot.SharedAccess == nil {
		t.Fatalf("confirmed shared case was not persisted: %+v", got)
	}
	r.shared = nil
	if err = s.syncCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	second, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.db.Close()
	if got := second.doc.Cases[caseID]; got.Status != "closed" {
		t.Fatalf("negative current generation did not close durable case: %+v", got)
	}
}

func TestOperationsTransactionOutlivesSetupBudget(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/(sentinel_(ieee_lease|acceptance)_[0-9]+|ps_discovery[0-9]+_test_[0-9]+)$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	state.beginLockedWithTimeout(50 * time.Millisecond)
	if state.lockErr != nil {
		t.Fatal(state.lockErr)
	}
	time.Sleep(70 * time.Millisecond)
	var one int
	if err = state.tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("setup timer canceled an active transaction: %v", err)
	}
	state.endLocked()
}

func TestAutomaticCaseSyncKeepsActionStateOutOfItsTransaction(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, _, assessment := caseSyncFixture()
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	s.operations = state
	state.doc.Actions["unrelated-action"] = EnforcementAction{ActionID: "unrelated-action"}
	if err = s.syncAutomaticCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.doc.Actions["unrelated-action"]; !ok {
		t.Fatal("automatic case synchronization replaced the shared action state")
	}
	caseID := proxyReviewCaseForSharedAssessment(assessment).CaseID
	var stored bool
	if err = state.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM risk_cases WHERE case_id=$1)`, caseID).Scan(&stored); err != nil || !stored {
		t.Fatalf("automatic case was not persisted: %v", err)
	}
}
