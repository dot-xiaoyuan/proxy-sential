package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/productpolicy"
	"proxy-sentinel/internal/store"
)

func TestProductPolicySnapshotAndImportTransaction(t *testing.T) {
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
	suffix := shortToken(12)
	source, snapshotID := "product-policy-test-"+suffix, "snapshot-"+suffix
	t.Cleanup(func() {
		cleanup := context.Background()
		_, _ = db.ExecContext(cleanup, `DELETE FROM policy_decision_records WHERE policy_id LIKE $1`, "srun4k:"+source+"%")
		_, _ = db.ExecContext(cleanup, `DELETE FROM account_policy_definitions WHERE id LIKE $1`, "srun4k:"+source+"%")
		_, _ = db.ExecContext(cleanup, `DELETE FROM policy_import_batches WHERE source=$1`, source)
		_, _ = db.ExecContext(cleanup, `DELETE FROM product_control_catalog WHERE source=$1`, source)
		_, _ = db.ExecContext(cleanup, `DELETE FROM product_catalog WHERE source=$1`, source)
		_, _ = db.ExecContext(cleanup, `DELETE FROM product_policy_snapshots WHERE source=$1`, source)
		_ = db.Close()
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	snapshot := productpolicy.Snapshot{SchemaVersion: productpolicy.SchemaVersion, Source: source, InstanceID: "redis-run", ObservedAt: now, Complete: true, Products: []productpolicy.Product{{ID: "p1", Name: "办公产品", ControlIDs: []string{"c1", "c2"}}}, Controls: []productpolicy.Control{{ID: "c1", Name: "基础", MaxOnlineNum: 2}, {ID: "c2", Name: "宽松", MaxOnlineNum: 4, DisableProxy: 1}}}
	if err = snapshot.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	created, resolved, err := commitProductPolicySnapshot(ctx, db, snapshotID, snapshot)
	if err != nil || !created || resolved != snapshotID {
		t.Fatalf("first commit: created=%t resolved=%s err=%v", created, resolved, err)
	}
	created, _, err = commitProductPolicySnapshot(ctx, db, snapshotID, snapshot)
	if err != nil || created {
		t.Fatalf("idempotent replay: created=%t err=%v", created, err)
	}
	conflict := snapshot
	conflict.Products = append([]productpolicy.Product{}, snapshot.Products...)
	conflict.Products[0].Name = "冲突产品"
	conflict.ContentHash = ""
	if err = conflict.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	if _, _, err = commitProductPolicySnapshot(ctx, db, snapshotID, conflict); !errors.Is(err, errProductPolicySnapshotConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	late := snapshot
	late.ObservedAt = now.Add(-time.Minute)
	late.Products = []productpolicy.Product{{ID: "late-product", Name: "迟到产品"}}
	late.Controls = nil
	late.ContentHash = ""
	if err = late.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	if created, _, err = commitProductPolicySnapshot(ctx, db, "late-"+suffix, late); err != nil || !created {
		t.Fatalf("late immutable snapshot not saved: created=%t err=%v", created, err)
	}
	var currentSnapshot string
	if err = db.QueryRowContext(ctx, `SELECT snapshot_id FROM product_catalog WHERE source=$1 AND product_id='p1' AND active`, source).Scan(&currentSnapshot); err != nil || currentSnapshot != snapshotID {
		t.Fatalf("late snapshot rewound current catalog: snapshot=%s err=%v", currentSnapshot, err)
	}

	server := &Server{productPolicies: newProductPolicyState("token", db)}
	body, _ := json.Marshal(map[string]string{"source": source})
	previewRequest := httptest.NewRequest(http.MethodPost, "/api/v1/policy-imports/preview", bytes.NewReader(body))
	previewResponse := httptest.NewRecorder()
	server.handlePolicyImportPreview(previewResponse, previewRequest)
	if previewResponse.Code != http.StatusCreated {
		t.Fatalf("preview: %d %s", previewResponse.Code, previewResponse.Body.String())
	}
	var batch struct {
		BatchID string `json:"batch_id"`
	}
	if json.Unmarshal(previewResponse.Body.Bytes(), &batch) != nil || batch.BatchID == "" {
		t.Fatal("preview batch missing")
	}
	publishResponse := httptest.NewRecorder()
	server.handlePolicyImportPublish(publishResponse, httptest.NewRequest(http.MethodPost, "/", nil), batch.BatchID)
	if publishResponse.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", publishResponse.Code, publishResponse.Body.String())
	}
	var mode, trigger, action string
	var enabled bool
	err = db.QueryRowContext(ctx, `SELECT document->>'mode',(document->>'enabled')::boolean,document->>'trigger',document->'stages'->0->>'action' FROM account_policy_definitions WHERE id=$1`, "srun4k:"+source+":product:p1:session_quota_exceeded").Scan(&mode, &enabled, &trigger, &action)
	if err != nil || mode != "observe" || !enabled || trigger != "session_quota_exceeded" || action != "record" {
		t.Fatalf("published policy mismatch mode=%s enabled=%t trigger=%s action=%s err=%v", mode, enabled, trigger, action, err)
	}
}
