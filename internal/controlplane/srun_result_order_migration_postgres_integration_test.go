package controlplane

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestSRunNativeResultOrderMigration(t *testing.T) {
	db := srunIsolatedReplayDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `CREATE TABLE srun4k_integrations(connector_id text PRIMARY KEY,connection_state text,last_error text,last_tested_at timestamptz,last_synced_at timestamptz,identity_accounts integer);INSERT INTO srun4k_integrations VALUES('kept','failed','retained failure','2026-09-30 00:00:00Z','2026-09-30 01:00:00Z',81)`); err != nil {
		t.Fatal(err)
	}
	digest := func() string {
		t.Helper()
		var hash string
		if err := db.QueryRowContext(ctx, `SELECT md5(to_jsonb(i)::text) FROM (SELECT connector_id,connection_state,last_error,last_tested_at,last_synced_at,identity_accounts FROM srun4k_integrations) i`).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		return hash
	}
	before := digest()
	body, err := os.ReadFile("../../migrations/postgres/079_srun4k_result_observation_order.sql")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "079_srun4k_result_observation_order.sql"), body, 0600); err != nil {
		t.Fatal(err)
	}
	held, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	if _, err = held.ExecContext(ctx, `LOCK TABLE srun4k_integrations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err = store.ApplyPostgresMigrations(ctx, os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), dir); err == nil {
		t.Fatal("blocked migration succeeded")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("migration exceeded lock budget")
	}
	var sequence sql.NullString
	var count int
	if err = db.QueryRowContext(ctx, `SELECT to_regclass('srun4k_operation_sequence')::text`).Scan(&sequence); err != nil || sequence.Valid {
		t.Fatal("partial sequence after rollback", err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name='srun4k_integrations' AND column_name LIKE '%result_order'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial columns after rollback", err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial migration ledger", err)
	}
	held.Rollback()
	result, err := store.ApplyPostgresMigrations(ctx, os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), dir)
	if err != nil || len(result.Applied) != 1 {
		t.Fatalf("retry failed: %+v %v", result, err)
	}
	if digest() != before {
		t.Fatal("existing results modified")
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_integrations WHERE last_test_result_order=0 AND last_sync_result_order=0 AND last_health_result_order=0`).Scan(&count); err != nil || count != 1 {
		t.Fatal("legacy baseline missing", err)
	}
	result, err = store.ApplyPostgresMigrations(ctx, os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), dir)
	if err != nil || len(result.Applied) != 0 {
		t.Fatal("migration not idempotent", err)
	}
}

func TestSRunNativeOperationAllocation(t *testing.T) {
	s, _ := srunIsolatedReplayServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var cache int64
	var cycle bool
	if err := s.operations.db.QueryRowContext(ctx, `SELECT cache_size,cycle FROM pg_sequences WHERE sequencename='srun4k_operation_sequence'`).Scan(&cache, &cycle); err != nil || cache != 1 || cycle {
		t.Fatal("sequence ordering configuration", cache, cycle, err)
	}
	a, err := s.operations.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := s.operations.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var previous int64
	for _, conn := range []*sql.Conn{a, b, a, b} {
		var n int64
		if err := conn.QueryRowContext(ctx, `SELECT nextval('srun4k_operation_sequence')`).Scan(&n); err != nil || n <= previous {
			t.Fatal("pooled connections did not preserve order", n, previous, err)
		}
		previous = n
	}
	item := srun4KIntegration{ConnectorID: "private", Host: "192.0.2.1", Source: "srun4k:private", SensorID: "private", ReconcileIntervalHours: 6}
	bound, err := s.beginSRunOperation(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	n := bound.Value(srunOperationOrderKey{}).(int64)
	if n <= previous {
		t.Fatal("allocator not globally ordered")
	}
	nested, err := s.beginSRunOperation(bound, item)
	if err != nil || nested.Value(srunOperationOrderKey{}) != n {
		t.Fatal("nested probe allocated another order", err)
	}
	changed := item
	changed.Host = "192.0.2.2"
	if _, err = s.beginSRunOperation(bound, changed); err == nil {
		t.Fatal("nested probe accepted changed host")
	}
	if err = s.operations.db.QueryRowContext(ctx, `SELECT last_value FROM srun4k_operation_sequence`).Scan(&previous); err != nil || previous != n {
		t.Fatal("reused/rejected operation advanced sequence", err)
	}
	if _, err = s.operations.db.ExecContext(ctx, `DROP SEQUENCE srun4k_operation_sequence`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.beginSRunOperation(ctx, item); err != errSRunTestResultCommit {
		t.Fatal("allocation failure escaped safe result error", err)
	}
}
