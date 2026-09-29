package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"strings"
	"testing"
	"time"
)

func TestPostgresPolicyReadsBypassOperationsLock(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	prefix := fmt.Sprintf("policy-read-test-%d", time.Now().UnixNano())
	for _, table := range []string{"account_policy_definitions", "account_policy_executions"} {
		defer db.ExecContext(context.Background(), "DELETE FROM "+table+" WHERE id LIKE $1", prefix+"%")
	}
	for i := 0; i < 2; i++ {
		p := policy.Definition{ID: fmt.Sprintf("%s-%d", prefix, i), Priority: i, Name: "共享上网", Trigger: "shared_access", Mode: "observe"}
		raw, _ := json.Marshal(p)
		if _, err = db.ExecContext(ctx, `INSERT INTO account_policy_definitions(id,document) VALUES($1,$2)`, p.ID, raw); err != nil {
			t.Fatal(err)
		}
		e := policy.Execution{ID: p.ID, PolicyID: p.ID, AccountID: fmt.Sprintf("%s-%d", prefix, i), Definition: p, EvidenceIDs: []string{"shared-evidence"}}
		raw, _ = json.Marshal(e)
		if _, err = db.ExecContext(ctx, `INSERT INTO account_policy_executions(id,document) VALUES($1,$2)`, e.ID, raw); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations')); LOCK risk_case_evidence_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ops := &operationsState{db: db}
	ops.mu.owner = ops
	ops.mu.Mutex.Lock()
	defer ops.mu.Mutex.Unlock()
	server := &Server{operations: ops, reader: noIdentityOnPolicyRead{}}
	for _, path := range []string{"/policies", "/policy-executions?account_id=" + url.QueryEscape(prefix+"-1")} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1"+path, nil)
		rctx, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		r = r.WithContext(rctx)
		w := httptest.NewRecorder()
		done := make(chan struct{})
		started := time.Now()
		go func() { defer close(done); server.handlePolicies(w, r, strings.Split(path, "?")[0]) }()
		select {
		case <-done:
		case <-rctx.Done():
			t.Fatal("policy read waited for unrelated operations lock")
		}
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		t.Logf("%s: %s", path, time.Since(started))
		if strings.HasPrefix(path, "/policy-executions") {
			var body struct {
				Items []policy.Execution `json:"items"`
			}
			json.Unmarshal(w.Body.Bytes(), &body)
			if len(body.Items) != 1 || body.Items[0].AccountID != prefix+"-1" {
				t.Fatal("account filter lost")
			}
		} else {
			var body struct {
				Items []policy.Definition `json:"items"`
			}
			json.Unmarshal(w.Body.Bytes(), &body)
			found := []string{}
			for _, p := range body.Items {
				if strings.HasPrefix(p.ID, prefix) {
					found = append(found, p.ID)
				}
			}
			if len(found) != 2 || found[0] != prefix+"-1" {
				t.Fatal("priority order lost")
			}
		}
	}
}

func TestPostgresPolicyWritesAreScopedAndImmediatelyVisible(t *testing.T) {
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
	id := "policy-scoped-" + shortToken(16)
	defer db.ExecContext(context.Background(), "DELETE FROM account_policy_definitions WHERE id=$1", id)
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations')); LOCK risk_case_evidence_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ops := &operationsState{db: db}
	ops.mu.Mutex.Lock()
	defer ops.mu.Mutex.Unlock()
	p := policy.Definition{ID: id, Name: "配置提交回放", Mode: "observe", Trigger: "shared_access"}
	saved, err := ops.writePolicyDefinition(ctx, p, true)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("scoped create: %+v %v", saved, err)
	}
	if _, err = ops.writePolicyDefinition(ctx, p, true); err != errPolicyConflict {
		t.Fatalf("duplicate create: %v", err)
	}
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() { _, err := ops.writePolicyDefinition(ctx, p, false); results <- err }()
	}
	for i := 0; i < 20; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	var revision int
	if err = db.QueryRowContext(ctx, `SELECT (document->>'revision')::int FROM account_policy_definitions WHERE id=$1`, id).Scan(&revision); err != nil || revision != 21 {
		t.Fatalf("committed revision=%d: %v", revision, err)
	}
}
