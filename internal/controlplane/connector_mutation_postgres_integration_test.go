package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestPostgresConnectorWritesAvoidUnrelatedLocks(t *testing.T) {
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
	id := fmt.Sprintf("connector-scoped-%d", time.Now().UnixNano())
	defer db.ExecContext(context.Background(), `DELETE FROM enforcement_connectors WHERE connector_id=$1`, id)
	initialServer := &Server{actionMasterKey: []byte("benchmark-isolated-master-key-1234")}
	encrypted, err := initialServer.encryptConnectorSecret("previous-isolated-secret")
	if err != nil {
		t.Fatal(err)
	}
	doc := emptyOperationsDocument()
	doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "previous configuration", EndpointURL: "http://127.0.0.1:19001", Mode: "shadow", Enabled: true, EncryptedSecret: encrypted, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	seedTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := &operationsState{db: db, tx: seedTx, doc: doc}
	if err = seed.saveLocked(); err != nil {
		seedTx.Rollback()
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
	ops := &operationsState{db: db}
	ops.mu.owner = ops
	ops.mu.Mutex.Lock()
	defer ops.mu.Mutex.Unlock()
	s := &Server{operations: ops, actionMasterKey: []byte("benchmark-isolated-master-key-1234")}
	results := make(chan *httptest.ResponseRecorder, 20)
	for i := 0; i < 20; i++ {
		go func() {
			raw, _ := json.Marshal(connectorRequest{ConnectorID: id, Name: "独立配置回放", EndpointURL: "http://127.0.0.1:19001", Mode: "shadow", Secret: "isolated-test-secret", Enabled: true})
			r := httptest.NewRequest("POST", "/api/v1/actions/connectors", strings.NewReader(string(raw))).WithContext(ctx)
			w := httptest.NewRecorder()
			s.handleActions(w, r)
			results <- w
		}()
	}
	for i := 0; i < 20; i++ {
		w := <-results
		if w.Code != 200 {
			t.Fatalf("save response=%d %s", w.Code, w.Body.String())
		}
		var name string
		if err := db.QueryRowContext(ctx, `SELECT name FROM enforcement_connectors WHERE connector_id=$1`, id).Scan(&name); err != nil || name != "独立配置回放" {
			t.Fatalf("success not immediately visible: name=%q err=%v", name, err)
		}
	}
	// Missing connectivity targets are rejected without a full document reload.
	r := httptest.NewRequest("POST", "/api/v1/actions/connectors/missing-scoped-test/test", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	s.handleActions(w, r)
	if w.Code != 404 {
		t.Fatalf("missing target: %d %s", w.Code, w.Body.String())
	}
	previous := stale.doc.Connectors[id]
	previous.ConsecutiveFailures = 1
	stale.doc.Connectors[id] = previous
	stale.tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = stale.saveLocked(); err == nil {
		t.Fatal("stale background connector overwrote newer configuration")
	}
	stale.tx.Rollback()
	var name string
	var actualSecret []byte
	if err = db.QueryRowContext(ctx, `SELECT name,encrypted_secret FROM enforcement_connectors WHERE connector_id=$1`, id).Scan(&name, &actualSecret); err != nil || name != "独立配置回放" || string(actualSecret) == encrypted {
		t.Fatalf("newer configuration lost: name=%q err=%v", name, err)
	}

}

func TestPostgresNativeConnectorTypePersistsWithoutHMAC(t *testing.T) {
	s, _ := taskIntegrationServer(t)
	id := "native-kind-" + shortToken(16)
	defer s.operations.db.Exec(`DELETE FROM enforcement_connectors WHERE connector_id=$1`, id)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	raw, _ := json.Marshal(connectorRequest{CertificatePEM: &certificate, ConnectorID: id, ConnectorType: "srun4k", Name: "原生测试", EndpointURL: "https://192.0.2.190", Mode: "shadow"})
	w := httptest.NewRecorder()
	s.handleActions(w, httptest.NewRequest("POST", "/api/v1/actions/connectors", strings.NewReader(string(raw))))
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	var kind string
	var secret []byte
	if err := s.operations.db.QueryRow(`SELECT connector_type,encrypted_secret FROM enforcement_connectors WHERE connector_id=$1`, id).Scan(&kind, &secret); err != nil || kind != "srun4k" || len(secret) != 0 {
		t.Fatalf("type or secret persistence incorrect: %s %v", kind, err)
	}
	doc := emptyOperationsDocument()
	if err := loadConnectorsScoped(context.Background(), s.operations.db, &doc, " WHERE connector_id=$1", []any{id}); err != nil || (doc.Connectors[id].ConnectorType != "srun4k" || doc.Connectors[id].CertificatePEM != strings.TrimSpace(certificate)) {
		t.Fatal("native type lost on reload", err)
	}
}
