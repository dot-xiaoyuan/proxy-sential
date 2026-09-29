package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestPostgresActionCallbacksAreScopedAndIdempotent(t *testing.T) {
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
	connector := fmt.Sprintf("callback-scoped-%d", time.Now().UnixNano())
	id := connector + "-action"
	secret := "isolated-signing-secret"
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_connectors WHERE connector_id=$1`, connector)
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_actions WHERE action_id=$1`, id)
	s := &Server{operations: &operationsState{db: db}, actionMasterKey: []byte("benchmark-isolated-master-key-1234")}
	s.operations.mu.owner = s.operations
	encrypted, err := s.encryptConnectorSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	doc := emptyOperationsDocument()
	doc.Connectors[connector] = ActionConnector{ConnectorID: connector, Name: "callback replay", EndpointURL: "http://127.0.0.1:19001", Mode: "active", Enabled: true, EncryptedSecret: encrypted, UpdatedAt: now}
	doc.Actions[id] = EnforcementAction{ActionID: id, ConnectorID: connector, IdempotencyKey: id, ActionType: "disconnect", SubjectType: "account", SubjectID: "fixture-account", Mode: "active", Status: "running", CreatedAt: now, UpdatedAt: now}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := &operationsState{db: db, tx: tx, doc: doc}
	if err = seed.saveLocked(); err != nil {
		tx.Rollback()
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
	s.operations.mu.Mutex.Lock()
	defer s.operations.mu.Mutex.Unlock()
	call := func(status string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]string{"action_id": id, "status": status, "error": "replay failure"})
		r := httptest.NewRequest("POST", "/api/v1/actions/callback", bytes.NewReader(raw)).WithContext(ctx)
		stamp := time.Now().UTC().Format(time.RFC3339Nano)
		r.Header.Set("X-Proxy-Sentinel-Timestamp", stamp)
		r.Header.Set("X-Proxy-Sentinel-Signature", signActionPayload(secret, stamp, raw))
		w := httptest.NewRecorder()
		s.handleActions(w, r)
		return w
	}
	results := make(chan *httptest.ResponseRecorder, 20)
	for i := 0; i < 20; i++ {
		go func() { results <- call("failed") }()
	}
	for i := 0; i < 20; i++ {
		w := <-results
		if w.Code != 200 {
			t.Fatalf("callback: %d %s", w.Code, w.Body.String())
		}
	}
	var failures int
	var status string
	if err = db.QueryRowContext(ctx, `SELECT a.status,c.consecutive_failures FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE a.action_id=$1`, id).Scan(&status, &failures); err != nil || status != "failed" || failures != 1 {
		t.Fatalf("status=%s failures=%d err=%v", status, failures, err)
	}
	previous := stale.doc.Actions[id]
	previous.Status = "succeeded"
	previous.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	stale.doc.Actions[id] = previous
	stale.tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = stale.saveLocked(); err == nil {
		t.Fatal("stale background action overwrote callback")
	}
	stale.tx.Rollback()
	if err = db.QueryRowContext(ctx, `SELECT status FROM enforcement_actions WHERE action_id=$1`, id).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("stale write changed action status: %s %v", status, err)
	}

}

func TestPostgresActionDeliveryReleasesTransactionAndIgnoresLateTransportFailure(t *testing.T) {
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
	id := fmt.Sprintf("delivery-scoped-%d", time.Now().UnixNano())
	connector := id + "-connector"
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_connectors WHERE connector_id=$1`, connector)
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_actions WHERE action_id=$1`, id)
	secret := "isolated-delivery-secret"
	entered, release := make(chan struct{}), make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Idempotency-Key") != id || r.Header.Get("X-Proxy-Sentinel-Signature") != signActionPayload(secret, r.Header.Get("X-Proxy-Sentinel-Timestamp"), body) {
			t.Error("external request lost durable idempotency or signature")
		}
		close(entered)
		<-release
		http.Error(w, "delayed transport failure", http.StatusServiceUnavailable)
	}))
	defer remote.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	s := &Server{operations: &operationsState{db: db}, actionMasterKey: []byte("benchmark-isolated-master-key-1234")}
	s.operations.mu.owner = s.operations
	encrypted, err := s.encryptConnectorSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	doc := emptyOperationsDocument()
	doc.Connectors[connector] = ActionConnector{ConnectorID: connector, Name: "scoped delivery", EndpointURL: remote.URL, Mode: "active", Enabled: true, EncryptedSecret: encrypted, UpdatedAt: now}
	doc.Actions[id] = EnforcementAction{ActionID: id, ConnectorID: connector, IdempotencyKey: id, ActionType: "disconnect", SubjectType: "account", SubjectID: "fixture-account", Mode: "active", Status: "pending", CreatedAt: now, UpdatedAt: now}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := &operationsState{db: db, tx: tx, doc: doc}
	if err = seed.saveLocked(); err != nil {
		tx.Rollback()
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
	s.operations.mu.Mutex.Lock()
	defer s.operations.mu.Mutex.Unlock()
	done := make(chan struct{})
	go func() { defer close(done); s.deliverAction(id, false) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("delivery waited on unrelated operations lock")
	}
	// A target receipt must commit while the network request is still blocked.
	if err = s.finishAction(id, "succeeded", "remote-completed", ""); err != nil {
		t.Fatalf("external request held its transaction: %v", err)
	}
	unblock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("delivery did not persist its late receipt")
	}
	var status string
	var retries, failures int
	if err = db.QueryRowContext(ctx, `SELECT a.status,a.retry_count,c.consecutive_failures FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE action_id=$1`, id).Scan(&status, &retries, &failures); err != nil || status != "succeeded" || retries != 0 || failures != 0 {
		t.Fatalf("late failure undid callback: status=%s retries=%d failures=%d err=%v", status, retries, failures, err)
	}
	// Simulate restart after the running intent committed, before its receipt.
	// Scheduling must not reload unrelated cases or acquire the old global lock.
	queued := make(chan string, 8)
	s.actionDeliveries = newActionDeliveryQueue(func(actionID string, _ bool) {
		// Other replay fixtures may also have due intents. The scheduler is
		// responsible for all of them; observe only this test’s durable identity.
		if actionID == id {
			queued <- actionID
		}
	})
	if _, err = db.ExecContext(ctx, `UPDATE enforcement_actions SET status='running',updated_at=now()-interval '2 minutes' WHERE action_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err = s.processDueActionsPostgres(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-queued:
		if got != id {
			t.Fatalf("recovered another intent: %s", got)
		}
	case <-ctx.Done():
		t.Fatal("restart did not recover running intent")
	}
	if err = db.QueryRowContext(ctx, `SELECT status,idempotency_key FROM enforcement_actions WHERE action_id=$1`, id).Scan(&status, &now); err != nil || status != "pending" || now != id {
		t.Fatalf("recovery lost durable identity: %s %s %v", status, now, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE enforcement_actions SET status='succeeded',expires_at=now()-interval '1 minute' WHERE action_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_actions WHERE parent_action_id=$1`, id)
	for i := 0; i < 2; i++ {
		if err = s.processDueActionsPostgres(time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	var releases int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM enforcement_actions WHERE parent_action_id=$1 AND action_type='release' AND idempotency_key=$2`, id, id+":release").Scan(&releases); err != nil || releases != 1 {
		t.Fatalf("expiry manufactured duplicate release: count=%d err=%v", releases, err)
	}
}
