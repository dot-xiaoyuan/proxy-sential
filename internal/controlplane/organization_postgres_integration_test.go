package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/store"
	"strings"
	"testing"
	"time"
)

// Replay unrelated evidence-table and in-process locks while reading/writing
// organization data, then verify a legacy transaction cannot overwrite it.
func TestOrganizationPostgresIndependentAndImmediatelyVisible(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
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
	id := fmt.Sprintf("org-perf-%d", time.Now().UnixNano())
	defer db.ExecContext(context.Background(), "DELETE FROM campuses WHERE campus_id=$1", id)
	ops := &operationsState{db: db}
	ops.mu.owner = ops
	s := &Server{operations: ops}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations')); LOCK risk_case_evidence_snapshots IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ops.mu.Mutex.Lock()
	defer ops.mu.Mutex.Unlock()
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
		rctx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		r = r.WithContext(rctx)
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { defer close(done); s.handleOrganization(w, r) }()
		select {
		case <-done:
		case <-rctx.Done():
			t.Fatal("organization waited for unrelated lock")
		}
		return w
	}
	for _, path := range []string{"/organization", "/organization?kind=campuses&limit=1", "/organization?kind=network_zones&limit=1"} {
		if w := call("GET", path, ""); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	raw, _ := json.Marshal(Campus{CampusID: id, Name: "立即可见"})
	if w := call("POST", "/organization/campuses", string(raw)); w.Code != 201 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if w := call("GET", "/organization", ""); !strings.Contains(w.Body.String(), id) {
		t.Fatal("committed campus not immediately visible")
	}
	apID := id + "-ap"
	defer db.ExecContext(context.Background(), "DELETE FROM access_points WHERE access_point_id=$1", apID)
	apBody, _ := json.Marshal(AccessPoint{AccessPointID: apID, CampusID: id, Name: "接入点", ManagementIP: "192.0.2.1"})
	if w := call("POST", "/organization/access-points", string(apBody)); w.Code != 201 {
		t.Fatalf("access point save: %d %s", w.Code, w.Body.String())
	}
	var before int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM access_points WHERE access_point_id<$1", apID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/organization", fmt.Sprintf("/organization?kind=access_points&limit=1&cursor=%d", before)} {
		w := call("GET", path, "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), apID) || !strings.Contains(w.Body.String(), `"management_ip":"192.0.2.1"`) || strings.Contains(w.Body.String(), "192.0.2.1/32") {
			t.Fatalf("access point address differs between whole and paged reads: %s %d %s", path, w.Code, w.Body.String())
		}
	}
	if w := call("POST", "/organization/buildings", `{"building_id":"x","campus_id":"missing"}`); w.Code != 400 {
		t.Fatalf("missing campus accepted: %d", w.Code)
	}
	if w := call("GET", "/organization?kind=invalid", ""); w.Code != 400 {
		t.Fatalf("unknown kind: %d", w.Code)
	}
}

func TestLegacySaveDoesNotOverwriteScopedOrganizationSave(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	id := fmt.Sprintf("org-race-%d", time.Now().UnixNano())
	defer db.ExecContext(ctx, "DELETE FROM campuses WHERE campus_id=$1", id)
	old := Campus{CampusID: id, Name: "旧名称", Enabled: true}
	doc := emptyOperationsDocument()
	doc.Campuses[id] = old
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveOrganizationRows(ctx, tx, doc); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	state := &operationsState{doc: doc, organizationBaseline: organizationFingerprints(doc)}
	next := emptyOperationsDocument()
	old.Name = "新名称"
	next.Campuses[id] = old
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveOrganizationRows(ctx, tx, next); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveOrganizationRows(ctx, tx, state.changedOrganization()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var name string
	if err = db.QueryRowContext(ctx, "SELECT name FROM campuses WHERE campus_id=$1", id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "新名称" {
		t.Fatalf("legacy save overwrote committed update: %s", name)
	}
}
