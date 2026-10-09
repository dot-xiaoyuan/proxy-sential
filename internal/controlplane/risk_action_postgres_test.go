package controlplane

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestPostgresRiskActionDeliveryReadsCurrentCaseWithoutGlobalLocks(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || (!strings.HasPrefix(u.Path, "/sentinel_ieee_lease_") && !strings.HasPrefix(u.Path, "/sentinel_acceptance_")) {
		t.Fatal("requires owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, _, a := riskActionReplay(t)
	item := s.operations.doc.Cases[a.CaseID]
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	item.SubjectType, item.SubjectID, item.Priority = "ip", item.IP, "high"
	item.FirstSeen, item.LastSeen, item.CreatedAt, item.UpdatedAt = stamp, stamp, stamp, stamp
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	state.mu.Lock()
	state.doc.Cases[item.CaseID] = item
	err = state.saveLocked()
	state.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s.operations = state
	lock, err := state.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations')); LOCK risk_case_evidence_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	state.mu.Mutex.Lock()
	defer state.mu.Mutex.Unlock()
	if err = s.validatePolicyDelivery(a); err != nil {
		t.Fatalf("valid current proof failed under unrelated locks: %v", err)
	}
	if _, err = state.db.ExecContext(ctx, `UPDATE risk_cases SET account_id='changed-owner',updated_at=clock_timestamp() WHERE case_id=$1`, a.CaseID); err != nil {
		t.Fatal(err)
	}
	if err = s.validatePolicyDelivery(a); err == nil {
		t.Fatal("stale cached case identity authorized delivery")
	}
	if state.doc.Cases[a.CaseID].AccountID != "account" {
		t.Fatal("test did not retain the stale cache needed to exercise current SQL read")
	}
}
