package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestDeviceRetentionProtectionAndBatches(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	// Temporary relations isolate this test from persistent application fixtures.
	for _, q := range []string{`CREATE TEMP TABLE risk_cases(ip inet)`, `CREATE TEMP TABLE risk_case_evidence_snapshots(evidence jsonb)`, `CREATE TEMP TABLE device_inventory_snapshots(run_id text,sensor_id text,"window" text,ip inet,created_at timestamptz,inventory jsonb NOT NULL DEFAULT '{}')`} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	installRetentionTestGuard(t, db)
	s := &PostgresStore{db: db}
	now := time.Now().UTC()
	old := now.Add(-10 * 24 * time.Hour)
	for _, r := range []struct {
		run, ip string
		at      time.Time
	}{{"old", "10.0.0.1", old}, {"new", "10.0.0.1", now}, {"old", "10.0.0.2", old}, {"new", "10.0.0.2", now}, {"only", "10.0.0.3", old}, {"older", "10.0.0.4", old.Add(-time.Hour)}, {"old", "10.0.0.4", old}, {"new", "10.0.0.4", now}} {
		if _, err = db.ExecContext(ctx, `INSERT INTO device_inventory_snapshots(run_id,sensor_id,"window",ip,created_at) VALUES($1,'s','1h',$2,$3)`, r.run, r.ip, r.at); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO risk_cases VALUES('10.0.0.2')`); err != nil {
		t.Fatal(err)
	}
	p, err := s.PreviewDeviceRetention(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	var eligible int64
	for _, d := range p.Days {
		eligible += d.Eligible
	}
	if eligible != 3 {
		t.Fatalf("preview: %+v", p)
	}
	for i := 0; i < 3; i++ {
		n, err := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 1)
		if err != nil || n != 1 {
			t.Fatal(n, err)
		}
	}
	if n, err := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 1); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	var n int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM device_inventory_snapshots").Scan(&n); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO device_inventory_snapshots(run_id,sensor_id,"window",ip,created_at) VALUES('older','s','1h','10.0.0.1',$1);`, old); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots VALUES('{"ip":"10.0.0.1"}')`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 10); err != nil || n != 0 {
		t.Fatal("historical evidence IP must be retained", n, err)
	}
	if _, err = db.ExecContext(ctx, `DELETE FROM risk_case_evidence_snapshots`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO risk_cases VALUES(NULL)`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 10); err != nil || n != 0 {
		t.Fatal("unknown case must block cleanup", n, err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots VALUES('{"ip":"invalid-ip"}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 10); err == nil {
		t.Fatal("invalid historical reference must fail closed")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.DeleteDeviceRetentionBatch(cancelled, p.Cutoff, 10); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestDeviceRetentionLimitsPhysicalBatchBytes(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TEMP TABLE risk_cases(ip inet)`,
		`CREATE TEMP TABLE risk_case_evidence_snapshots(evidence jsonb)`,
		`CREATE TEMP TABLE device_inventory_snapshots(run_id text,sensor_id text,"window" text,ip inet,created_at timestamptz,inventory jsonb)`,
		`INSERT INTO device_inventory_snapshots SELECT 'old-'||n,'s','1h',('192.0.2.'||n)::inet,now()-interval '10 days',jsonb_build_object('data',(SELECT string_agg(md5(i::text),'') FROM generate_series(1,250000) i)) FROM generate_series(1,2) n`,
		`INSERT INTO device_inventory_snapshots SELECT 'new','s','1h',('192.0.2.'||n)::inet,now(),'{}'::jsonb FROM generate_series(1,2) n`,
	} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	var bytes int64
	if err = db.QueryRowContext(ctx, `SELECT min(pg_column_size(inventory)) FROM device_inventory_snapshots WHERE run_id LIKE 'old-%'`).Scan(&bytes); err != nil || bytes <= 4<<20 {
		t.Fatalf("fixture must exceed half budget: %d, %v", bytes, err)
	}
	installRetentionTestGuard(t, db)
	s := &PostgresStore{db: db}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	// The row limit allows both, but the physical-byte limit must split them.
	for i := 0; i < 2; i++ {
		n, err := s.DeleteDeviceRetentionBatch(ctx, cutoff, 100)
		if err != nil || n != 1 {
			t.Fatal(n, err)
		}
	}
	if n, err := s.DeleteDeviceRetentionBatch(ctx, cutoff, 100); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func installRetentionTestGuard(t *testing.T, db *sql.DB) {
	t.Helper()
	raw, err := os.ReadFile("../../migrations/postgres/024_device_retention_reference_guard.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(string(raw)); err != nil {
		t.Fatal(err)
	}
}
