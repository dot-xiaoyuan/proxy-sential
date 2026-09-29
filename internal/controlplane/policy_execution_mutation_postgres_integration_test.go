package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

func TestPostgresPolicyExecutionRevokeIsScopedAndRejectsStaleBackground(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := fmt.Sprintf("execution-scoped-%d", time.Now().UnixNano())
	defer db.ExecContext(context.Background(), `DELETE FROM account_policy_executions WHERE id=$1`, id)
	ex := policy.Execution{ID: id, PolicyID: "fixture-manual", AccountID: "fixture-account", State: "awaiting_approval"}
	doc := emptyOperationsDocument()
	doc.PolicyExecutions[id] = ex
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = savePolicyDocuments(ctx, tx, doc); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	stale := &operationsState{db: db}
	if err = stale.reloadPostgres(ctx, db); err != nil {
		t.Fatal(err)
	}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations')); LOCK risk_case_evidence_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	s := &Server{operations: &operationsState{db: db}}
	s.operations.mu.owner = s.operations
	s.operations.mu.Mutex.Lock()
	defer s.operations.mu.Mutex.Unlock()
	responses := make(chan *httptest.ResponseRecorder, 20)
	for i := 0; i < 20; i++ {
		go func() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/v1/policy-executions/"+id+"/revoke", nil).WithContext(ctx)
			s.handlePolicyExecutionMutation(w, r, "/policy-executions/"+id+"/revoke")
			responses <- w
		}()
	}
	for i := 0; i < 20; i++ {
		w := <-responses
		if w.Code != 200 {
			t.Fatalf("revoke waited on unrelated lock: %d %s", w.Code, w.Body.String())
		}
		var got policy.Execution
		if err = json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.State != "revoked" {
			t.Fatalf("invalid business result: %s %v", w.Body.String(), err)
		}
	}
	previous := stale.doc.PolicyExecutions[id]
	previous.State = "pending_action"
	stale.doc.PolicyExecutions[id] = previous
	stale.tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = stale.saveLocked(); err == nil {
		t.Fatal("stale worker undid synchronous execution revoke")
	}
	stale.tx.Rollback()
	var state string
	if err = db.QueryRowContext(ctx, `SELECT document->>'state' FROM account_policy_executions WHERE id=$1`, id).Scan(&state); err != nil || state != "revoked" {
		t.Fatalf("revoke was not immediately visible: %s %v", state, err)
	}
}
