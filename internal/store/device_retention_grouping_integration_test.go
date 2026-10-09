package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestDeviceRetentionGroupingPreservesLatestRunTiesAndDeviceScopes(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, q := range []string{`CREATE TEMP TABLE risk_cases(ip inet)`, `CREATE TEMP TABLE risk_case_evidence_snapshots(evidence jsonb)`, `CREATE TEMP TABLE device_inventory_snapshots(run_id text,sensor_id text,"window" text,ip inet,created_at timestamptz,inventory jsonb NOT NULL DEFAULT '{}')`} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	installRetentionTestGuard(t, db)
	now := time.Now().UTC()
	old := now.Add(-10 * 24 * time.Hour)
	rows := []struct {
		run, sensor, window, ip string
		days                    int
	}{
		{"z", "s1", "1h", "192.0.2.1", 0}, {"a", "s1", "1h", "192.0.2.1", 0},
		// The latest run's older row must survive even with a newer per-IP row.
		{"z", "s1", "1h", "192.0.2.2", 2}, {"a", "s1", "1h", "192.0.2.2", 1},
		{"b", "s1", "1h", "192.0.2.3", 2},
		{"p-old", "s1", "1h", "192.0.2.5", 3}, {"p-new", "s1", "1h", "192.0.2.5", 2},
		{"a", "s1", "1h", "192.0.2.4", 2}, {"b", "s1", "1h", "192.0.2.4", 1},
		{"s2-a", "s2", "1h", "192.0.2.1", 2}, {"s2-z", "s2", "1h", "192.0.2.1", 1},
		{"w-old", "s1", "24h", "192.0.2.1", 3}, {"w-new", "s1", "24h", "192.0.2.1", 2},
	}
	for _, r := range rows {
		if _, err = db.ExecContext(ctx, `INSERT INTO device_inventory_snapshots(run_id,sensor_id,"window",ip,created_at) VALUES($1,$2,$3,$4,$5)`, r.run, r.sensor, r.window, r.ip, old.Add(-time.Duration(r.days)*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots VALUES('{"ip":"192.0.2.5"}')`); err != nil {
		t.Fatal(err)
	}
	s := &PostgresStore{db: db}
	p, err := s.PreviewDeviceRetention(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	var eligible int64
	for _, d := range p.Days {
		eligible += d.Eligible
	}
	if eligible != 4 {
		t.Fatal("reference protection changed", eligible)
	}
	for i := 0; i < 4; i++ {
		if n, e := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 1); e != nil || n != 1 {
			t.Fatal("eligible batch", i, n, e)
		}
	}
	if n, e := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 1); e != nil || n != 0 {
		t.Fatal("no remaining eligible snapshots", n, e)
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM device_inventory_snapshots`).Scan(&count); err != nil || count != 9 {
		t.Fatal("protected row count", count, err)
	}
	for _, run := range []string{"z", "p-old", "p-new", "s2-z", "w-new"} {
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM device_inventory_snapshots WHERE run_id=$1`, run).Scan(&count); err != nil || count < 1 {
			t.Fatal("protected run lost", run, count, err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO device_inventory_snapshots(run_id,sensor_id,"window",ip,created_at) VALUES('newly-eligible-old','s1','1h','192.0.2.1',$1)`, old.Add(-5*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, err = db.ExecContext(ctx, `INSERT INTO risk_cases VALUES(NULL)`); err != nil {
		t.Fatal(err)
	}
	if n, e := s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, 10); e != nil || n != 0 {
		t.Fatal("unbound case must still fail closed", n, e)
	}
}
