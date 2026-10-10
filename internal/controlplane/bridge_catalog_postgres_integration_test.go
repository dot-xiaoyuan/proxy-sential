package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/productpolicy"
	"proxy-sentinel/internal/store"
)

// Run only in the isolated acceptance database, never in the site database.
func TestManagedBridgeCatalogAndDirectoryTransaction(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defaults := IdentityBridgeDefaults{BridgeID: "bridge-catalog-test-" + shortToken(8), Source: "ncu-srun4k-test-" + shortToken(8)}.normalized()
	if _, err = db.ExecContext(ctx, `INSERT INTO identity_bridge_configs(bridge_id,desired_host) VALUES($1,'222.204.3.224');`, defaults.BridgeID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO identity_bridge_runtime(bridge_id,active_host,active_config_version,last_snapshot_at) VALUES($1,'222.204.3.224',1,$2)`, defaults.BridgeID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer db.Close()
		_, _ = db.Exec(`DELETE FROM audit_logs WHERE target=$1`, defaults.BridgeID)
		_, _ = db.Exec(`DELETE FROM product_control_catalog WHERE source=$1`, defaults.Source)
		_, _ = db.Exec(`DELETE FROM product_catalog WHERE source=$1`, defaults.Source)
		_, _ = db.Exec(`DELETE FROM product_policy_snapshots WHERE source=$1`, defaults.Source)
		_, _ = db.Exec(`DELETE FROM identity_bridge_configs WHERE bridge_id=$1`, defaults.BridgeID)
	})
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true, AllowIdentityIngest: true})
	s.identityBridge = defaults
	s.operations.db = db
	s.productPolicies.db = db
	s.identityIngest.key = "bridge-token"
	value := bridgeCatalogFixture("222.204.3.224", 1)
	value.Snapshot.Source = defaults.Source
	value.Snapshot.ContentHash = ""
	if err = value.Snapshot.NormalizeAndValidate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	post := func(value productpolicy.BridgeCatalogSnapshot, id string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(value)
		r := httptest.NewRequest(http.MethodPost, productpolicy.BridgeCatalogPath, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer bridge-token")
		r.Header.Set("Idempotency-Key", id)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := post(value, value.ID()); w.Code != http.StatusAccepted {
		t.Fatalf("commit=%d %s", w.Code, w.Body.String())
	}
	if w := post(value, value.ID()); w.Code != http.StatusOK {
		t.Fatalf("replay=%d %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	s.handle4KDirectory(w, httptest.NewRequest(http.MethodGet, "/api/v1/integrations/4k-directory", nil))
	var directory fourKDirectory
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &directory) != nil || directory.Source != defaults.Source || len(directory.Products) != 1 || directory.Products[0].Name != "测试产品" {
		t.Fatalf("directory=%s", w.Body.String())
	}
	var policies, actions, connectors int
	if err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM account_policy_definitions),(SELECT count(*) FROM enforcement_actions),(SELECT count(*) FROM enforcement_connectors)`).Scan(&policies, &actions, &connectors); err != nil || policies != 0 || actions != 0 || connectors != 0 {
		t.Fatalf("catalog created business state: %d/%d/%d err=%v", policies, actions, connectors, err)
	}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lock.ExecContext(ctx, `LOCK TABLE audit_logs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	next := value
	next.Snapshot.Products = []productpolicy.Product{{ID: "p2", Name: "应回滚产品"}}
	next.Snapshot.ObservedAt = value.Snapshot.ObservedAt.Add(time.Microsecond)
	next.Snapshot.ContentHash = ""
	if err = next.Snapshot.NormalizeAndValidate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	shortCtx, shortCancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, _, err = commitBridgeCatalogSnapshot(shortCtx, db, defaults, next.ID(), next)
	shortCancel()
	_ = lock.Rollback()
	if err == nil {
		t.Fatal("audit timeout did not roll back snapshot")
	}
	var active int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM product_catalog WHERE source=$1 AND product_id='p1' AND active`, defaults.Source).Scan(&active); err != nil || active != 1 {
		t.Fatal("failed commit changed active catalog")
	}
	if _, err = db.ExecContext(ctx, `UPDATE identity_bridge_runtime SET active_host='222.204.3.225',active_config_version=2 WHERE bridge_id=$1`, defaults.BridgeID); err != nil {
		t.Fatal(err)
	}
	if w := post(value, value.ID()); w.Code != http.StatusConflict {
		t.Fatalf("late old-host data accepted: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handle4KDirectory(w, httptest.NewRequest(http.MethodGet, "/api/v1/integrations/4k-directory", nil))
	if json.Unmarshal(w.Body.Bytes(), &directory) != nil || len(directory.Products) != 0 {
		t.Fatalf("old host catalog leaked: %s", w.Body.String())
	}
}
