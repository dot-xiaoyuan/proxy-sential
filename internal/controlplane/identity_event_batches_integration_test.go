package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/identityprotocol"
	"proxy-sentinel/internal/store"
	"sort"
	"testing"
	"time"
)

func TestIdentityBatchPhasesDoNotTreatAcceptanceAsCompletion(t *testing.T) {
	tests := []struct {
		status, export      string
		projected, count    int
		archive, projection string
	}{
		{"accepted", "pending", 0, 2, "pending", "pending"},
		{"completed", "processing", 2, 2, "pending", "completed"},
		{"processing", "completed", 1, 2, "completed", "pending"},
		{"completed", "completed", 2, 2, "completed", "completed"},
		{"failed", "failed", 0, 2, "failed", "failed"},
	}
	for _, tc := range tests {
		archive, projection := identityBatchPhases(tc.status, tc.export, tc.projected, tc.count)
		if archive != tc.archive || projection != tc.projection {
			t.Fatalf("%+v -> %s/%s", tc, archive, projection)
		}
	}
}

func TestDurableIdentityHTTPDoesNotWaitForDerivedStorage(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	if _, err := store.ApplyPostgresMigrations(context.Background(), dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	rawWrites := 0
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawWrites++
		http.Error(w, "derived storage unavailable", 503)
	}))
	defer ch.Close()
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, PostgresDSN: dsn, ClickHouseDSN: ch.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	scope := store.IdentityScope{Source: "radius", SensorID: fmt.Sprintf("http-inbox-%d", time.Now().UnixNano()), CampusID: "east", AccessDomain: "wifi"}
	server := &Server{reader: backend, identityIngest: &identityIngestState{key: "test-token"}, identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
	request := identityprotocol.Request{Source: scope.Source, SensorID: scope.SensorID, Records: []map[string]string{{"entity_role": "endpoint", "account_id": "student", "session_id": "session", "ip": "192.0.2.1", "campus_id": scope.CampusID, "access_domain": scope.AccessDomain, "action": "login", "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}}}
	run := func(id string) (identityprotocol.Receipt, int) {
		t.Helper()
		body, _ := json.Marshal(request)
		r := httptest.NewRequest("POST", "/api/v1/integrations/identity/event-batches", bytes.NewReader(body))
		r.Header.Set("Idempotency-Key", id)
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		server.handleDurableIdentityBatch(w, r)
		var receipt identityprotocol.Receipt
		_ = json.Unmarshal(w.Body.Bytes(), &receipt)
		return receipt, w.Code
	}
	id := scope.SensorID + "-lost-response"
	first, status := run(id)
	if status != 202 {
		t.Fatalf("accept status=%d", status)
	}
	registrations := server.identitySources
	server.identitySources = nil // configuration may change after a committed response is lost
	second, status := run(id)
	server.identitySources = registrations
	if status != 202 || first != second {
		t.Fatalf("lost-response retry changed receipt: %+v %+v %d", first, second, status)
	}
	if err = first.Verify(id, request.Hash(), 1); err != nil {
		t.Fatal(err)
	}
	request.Records[0]["ip"] = "192.0.2.2"
	if _, status = run(id); status != 409 {
		t.Fatalf("content collision status=%d", status)
	}
	samples := []time.Duration{}
	for i := 0; i < 100; i++ {
		begin := time.Now()
		if _, status = run(fmt.Sprintf("%s-%d", scope.SensorID, i)); status != 202 {
			t.Fatalf("accept %d", status)
		}
		samples = append(samples, time.Since(begin))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	t.Logf("durable HTTP p95=%s while ClickHouse is unavailable", samples[94])
	if samples[94] > time.Second {
		t.Fatal("durable acceptance SLO exceeded")
	}
	if rawWrites != 0 {
		t.Fatalf("HTTP ingress wrote ClickHouse %d times", rawWrites)
	}
}

func TestDurableIdentityHTTPWaitsForBriefScopeLock(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	if _, err := store.ApplyPostgresMigrations(context.Background(), dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, PostgresDSN: dsn, ClickHouseDSN: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	scope := store.IdentityScope{Source: "radius", SensorID: fmt.Sprintf("http-lock-%d", time.Now().UnixNano()), CampusID: "east", AccessDomain: "wifi"}
	server := &Server{reader: backend, identityIngest: &identityIngestState{key: "test-token"}, identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
	request := identityprotocol.Request{Source: scope.Source, SensorID: scope.SensorID, Records: []map[string]string{{"entity_role": "endpoint", "account_id": "student", "session_id": "session-1", "ip": "192.0.2.1", "campus_id": scope.CampusID, "access_domain": scope.AccessDomain, "action": "login", "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}}}
	send := func(id string) int {
		body, _ := json.Marshal(request)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/event-batches", bytes.NewReader(body))
		r.Header.Set("Idempotency-Key", id)
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		server.handleDurableIdentityBatch(w, r)
		return w.Code
	}
	if status := send(scope.SensorID + "-first"); status != http.StatusAccepted {
		t.Fatalf("first accept status=%d", status)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE identity_pipeline_scopes SET enabled=true WHERE scope_key=$1`, store.IdentityScopeKey(scope)); err != nil {
		t.Fatal(err)
	}
	released := make(chan error, 1)
	go func() {
		time.Sleep(3200 * time.Millisecond)
		released <- tx.Commit()
	}()
	request.Records[0]["session_id"] = "session-2"
	started := time.Now()
	status := send(scope.SensorID + "-second")
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	if status != http.StatusAccepted || time.Since(started) < time.Second {
		t.Fatalf("brief scope lock should return durable receipt: status=%d elapsed=%s", status, time.Since(started))
	}
}
func TestLegacyFailedBatchCannotReturnSuccess(t *testing.T) {
	server := &Server{identityIngest: &identityIngestState{key: "token", batches: map[string]IdentityIngestBatch{"failed": {BatchID: "failed", Status: "failed"}}}}
	response := runAuthorityBatch(t, server, authorityBatchRequest(1), "failed")
	if response.Code >= 200 && response.Code < 300 {
		t.Fatalf("failed batch returned %d", response.Code)
	}
}
