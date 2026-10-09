package store

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDeviceInventoryExpressionStatisticsMigration(t *testing.T) {
	const version = "077_device_inventory_expression_statistics.sql"
	body, err := os.ReadFile("../../migrations/postgres/" + version)
	if err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE device_inventory_snapshots(run_id text PRIMARY KEY,inventory jsonb NOT NULL)`,
		`INSERT INTO device_inventory_snapshots SELECT n::text,jsonb_build_object('devices',jsonb_build_array(jsonb_build_object('device_id','fixture-'||n,'raw',(SELECT string_agg(md5(i::text),'') FROM generate_series(1,2048) i)))) FROM generate_series(1,100) n`,
		`CREATE INDEX idx_device_inventory_candidate_ids ON device_inventory_snapshots USING gin((inventory->'devices') jsonb_path_ops)`,
		`CREATE SEQUENCE sentinel_test_stats_calls`,
		// This instrumented immutable accessor is confined to the test database.
		// Counting calls proves whether ANALYZE evaluates the expression before the
		// wide-value guard; it is never installed in production.
		`CREATE FUNCTION sentinel_test_stats_devices(j jsonb) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM nextval('public.sentinel_test_stats_calls'); RETURN j->'devices'; END $$`,
		`CREATE INDEX sentinel_test_stats_probe ON device_inventory_snapshots USING gin(sentinel_test_stats_devices(inventory) jsonb_path_ops)`,
		`SELECT setval('sentinel_test_stats_calls',1,false)`,
		`ANALYZE device_inventory_snapshots`,
	} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	calls := func() int64 {
		t.Helper()
		var n int64
		if e := db.QueryRowContext(ctx, `SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM sentinel_test_stats_calls`).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	if n := calls(); n < 100 {
		t.Fatalf("baseline did not evaluate wide expression samples: %d", n)
	}
	t.Log("baseline ANALYZE evaluated large expression for all sampled rows")
	var beforeOID, beforeNode int64
	var beforeHash string
	if err = db.QueryRowContext(ctx, `SELECT oid::bigint,relfilenode::bigint FROM pg_class WHERE oid='idx_device_inventory_candidate_ids'::regclass`).Scan(&beforeOID, &beforeNode); err != nil {
		t.Fatal(err)
	}
	digest := func() string {
		var s string
		if e := db.QueryRowContext(ctx, `SELECT md5(string_agg(md5(inventory::text),'' ORDER BY run_id)) FROM device_inventory_snapshots`).Scan(&s); e != nil {
			t.Fatal(e)
		}
		return s
	}
	beforeHash = digest()
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, version), body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE schema_migrations(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	t.Run("lock_conflict_rolls_back_and_can_retry", func(t *testing.T) {
		lock, e := db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer lock.Rollback()
		if _, e = lock.ExecContext(ctx, `ALTER INDEX idx_device_inventory_candidate_ids ALTER COLUMN 1 SET STATISTICS 42`); e != nil {
			t.Fatal(e)
		}
		start := time.Now()
		_, e = ApplyPostgresMigrations(ctx, dsn, dir)
		if e == nil || time.Since(start) > 4*time.Second {
			t.Fatal("lock deadline ignored", e, time.Since(start))
		}
		var ledger, target int
		if e = db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&ledger); e != nil {
			t.Fatal(e)
		}
		if e = db.QueryRowContext(ctx, `SELECT coalesce(attstattarget,-1) FROM pg_attribute WHERE attrelid='idx_device_inventory_candidate_ids'::regclass AND attnum=1`).Scan(&target); e != nil {
			t.Fatal(e)
		}
		if ledger != 0 || target != -1 {
			t.Fatal("failed migration escaped atomic rollback", ledger, target)
		}
		if e = lock.Rollback(); e != nil {
			t.Fatal(e)
		}
	})
	result, err := ApplyPostgresMigrations(ctx, dsn, dir)
	if err != nil || len(result.Applied) != 1 {
		t.Fatal(result, err)
	}
	if result, err = ApplyPostgresMigrations(ctx, dsn, dir); err != nil || len(result.Applied) != 0 {
		t.Fatal("idempotence", result, err)
	}
	var target int
	if err = db.QueryRowContext(ctx, `SELECT attstattarget FROM pg_attribute WHERE attrelid='idx_device_inventory_candidate_ids'::regclass AND attnum=1`).Scan(&target); err != nil || target != 0 {
		t.Fatal(target, err)
	}
	// Test the exact PostgreSQL skip mechanism on the instrumented accessor too.
	for _, q := range []string{`ALTER INDEX sentinel_test_stats_probe ALTER COLUMN 1 SET STATISTICS 0`, `SELECT setval('sentinel_test_stats_calls',1,false)`, `ANALYZE device_inventory_snapshots`} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if n := calls(); n != 0 {
		t.Fatalf("disabled expression statistics still read wide inventories: %d", n)
	}
	var oid, node int64
	if err = db.QueryRowContext(ctx, `SELECT oid::bigint,relfilenode::bigint FROM pg_class WHERE oid='idx_device_inventory_candidate_ids'::regclass`).Scan(&oid, &node); err != nil || oid != beforeOID || node != beforeNode {
		t.Fatal("index was replaced", oid, node, err)
	}
	if digest() != beforeHash {
		t.Fatal("inventory content changed")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL enable_seqscan=off`); err != nil {
		t.Fatal(err)
	}
	var plan string
	if err = tx.QueryRowContext(ctx, `EXPLAIN (FORMAT JSON) SELECT run_id FROM device_inventory_snapshots WHERE inventory->'devices' @> '[{"device_id":"fixture-1"}]'::jsonb`).Scan(&plan); err != nil || !strings.Contains(plan, "idx_device_inventory_candidate_ids") {
		t.Fatal("GIN lookup unavailable", plan, err)
	}
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT run_id FROM device_inventory_snapshots WHERE inventory->'devices' @> '[{"device_id":"fixture-1"}]'::jsonb`).Scan(&id); err != nil || id != "1" {
		t.Fatal("candidate lookup changed", id, err)
	}
	t.Log("wide expression evaluation skipped; GIN lookup, index identity and raw inventory retained")
}
