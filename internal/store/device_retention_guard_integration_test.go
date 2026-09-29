package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestRetentionReferenceGuards(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := fmt.Sprintf("retention_guard_%d", time.Now().UnixNano())
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
	cfg.RuntimeParams["search_path"] = schema + ",public"
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	db.SetMaxOpenConns(3)
	for _, q := range []string{
		`CREATE TABLE risk_cases(ip inet)`,
		`CREATE TABLE risk_case_evidence_snapshots(evidence jsonb)`,
		`CREATE TABLE device_inventory_snapshots(run_id text,sensor_id text,"window" text,ip inet,created_at timestamptz,inventory jsonb DEFAULT '{}')`,
		`INSERT INTO device_inventory_snapshots SELECT 'old','s','1h',('192.0.2.'||n)::inet,now()-interval '10 days','{}'::jsonb FROM generate_series(1,2) n`,
		`INSERT INTO device_inventory_snapshots SELECT 'new','s','1h',('192.0.2.'||n)::inet,now(),'{}'::jsonb FROM generate_series(1,2) n`,
	} {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := &PostgresStore{db: db}
	ctx := context.Background()
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	if _, err = s.DeleteDeviceRetentionBatch(ctx, cutoff, 10); err == nil || !strings.Contains(err.Error(), "guard migration") {
		t.Fatal("unguarded deletion accepted", err)
	}
	installRetentionTestGuard(t, db)
	writer, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err = writer.Exec(`INSERT INTO risk_cases VALUES('192.0.2.1')`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteDeviceRetentionBatch(ctx, cutoff, 10); n != 0 || err == nil || !strings.Contains(err.Error(), "guard busy") {
		t.Fatal("uncommitted case must fence deletion", n, err)
	}
	if err = writer.Commit(); err != nil {
		t.Fatal(err)
	}
	// A held retention guard must leave unrelated case writes available.
	guard, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Rollback()
	if _, err = guard.Exec(`SELECT pg_advisory_xact_lock_shared(hashtextextended('sentinel:inventory-reference:global',0)),pg_advisory_xact_lock(hashtextextended('sentinel:inventory-reference:ip:192.0.2.2',0))`); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `SET lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO risk_cases VALUES('192.0.2.99')`); err != nil {
		t.Fatal("unrelated case blocked", err)
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots VALUES('{"ip":"192.0.2.2"}')`); err == nil {
		t.Fatal("conflicting reference not fenced")
	}
	if _, err = conn.ExecContext(ctx, `INSERT INTO risk_cases VALUES(NULL)`); err == nil {
		t.Fatal("unknown reference not fenced")
	}
	guard.Rollback()
	conn.Close()
	// Only the unreferenced old snapshot is removed; the committed case survives.
	if n, err := s.DeleteDeviceRetentionBatch(ctx, cutoff, 10); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	var remaining int
	if err = db.QueryRow(`SELECT count(*) FROM device_inventory_snapshots WHERE run_id='old' AND ip='192.0.2.1'`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatal(remaining, err)
	}
}
