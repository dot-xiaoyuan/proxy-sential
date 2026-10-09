package controlplane

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
)

func TestSRunGroupNativeLegacyMigration(t *testing.T) {
	db := srunIsolatedReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, stmt := range []string{
		`CREATE TABLE srun4k_group_catalog(source text,group_id text,name text,parent_id text NOT NULL DEFAULT '',path text NOT NULL DEFAULT '',active boolean,observed_at timestamptz,updated_at timestamptz DEFAULT now(),PRIMARY KEY(source,group_id))`,
		`CREATE TABLE audit_logs(audit_id text PRIMARY KEY,actor text,action text,target text,outcome text,created_at timestamptz)`,
		`INSERT INTO srun4k_group_catalog(source,group_id,name,active,observed_at) VALUES('legacy-a','1','kept active',true,'2026-09-30 00:00:00Z'),('legacy-a','2','kept inactive',false,'2026-09-30 00:01:00Z'),('legacy-b','3','all inactive',false,'2026-09-30 00:02:00Z')`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	digest := func() string {
		t.Helper()
		var hash string
		if err := db.QueryRowContext(ctx, `SELECT md5(jsonb_agg(to_jsonb(g) ORDER BY source,group_id)::text) FROM srun4k_group_catalog g`).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	before := digest()
	body, err := os.ReadFile("../../migrations/postgres/078_srun4k_group_snapshot_order.sql")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "078_srun4k_group_snapshot_order.sql"), body, 0600); err != nil {
		t.Fatal(err)
	}
	held, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	if _, err = held.ExecContext(ctx, `LOCK TABLE srun4k_group_catalog IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err = store.ApplyPostgresMigrations(ctx, os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), dir); err == nil {
		t.Fatal("blocked migration succeeded")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("migration exceeded its lock budget")
	}
	var table sql.NullString
	if err = db.QueryRowContext(ctx, `SELECT to_regclass('srun4k_group_snapshots')::text`).Scan(&table); err != nil || table.Valid {
		t.Fatal("blocked migration left partial table", err)
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil || count != 0 {
		t.Fatal("blocked migration left applied ledger")
	}
	held.Rollback()
	result, err := store.ApplyPostgresMigrations(ctx, os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), dir)
	if err != nil || len(result.Applied) != 1 {
		t.Fatalf("migration retry failed: %+v %v", result, err)
	}
	if before != digest() {
		t.Fatal("migration mutated existing catalog rows")
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_group_snapshots WHERE legacy_import AND content_sha256 IS NULL`).Scan(&count); err != nil || count != 2 {
		t.Fatal("legacy baseline provenance missing")
	}
	if err = db.QueryRowContext(ctx, `SELECT jsonb_array_length(groups) FROM srun4k_group_snapshots WHERE source='legacy-b'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("all-inactive baseline not preserved as empty directory")
	}
	s := &Server{operations: &operationsState{db: db}}
	at := time.Date(2026, 9, 30, 0, 1, 0, 0, time.UTC)
	if err = s.commitSRunGroups(ctx, "legacy-a", []srunapi.Group{{ID: "1", Name: "kept active"}}, at); err != nil {
		t.Fatal("matching legacy retry not recognized", err)
	}
	if err = s.commitSRunGroups(ctx, "legacy-a", []srunapi.Group{{ID: "stale", Name: "stale"}}, at.Add(-time.Minute)); err == nil {
		t.Fatal("migration did not fence older catalog")
	}
	result, err = store.ApplyPostgresMigrations(ctx, os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), dir)
	if err != nil || len(result.Applied) != 0 {
		t.Fatal("migration rerun not idempotent")
	}
}
