package store

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestDeviceRetentionLockedCandidatesAreNotExhausted(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(3)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, q := range []string{
		`CREATE TABLE risk_cases(ip inet)`, `CREATE TABLE risk_case_evidence_snapshots(evidence jsonb)`,
		`CREATE TABLE device_inventory_snapshots(run_id text,sensor_id text,"window" text,ip inet,created_at timestamptz,inventory jsonb NOT NULL DEFAULT '{}')`,
		`INSERT INTO device_inventory_snapshots VALUES('old-a','s','1h','192.0.2.1',now()-interval '10 days','{}'),('old-b','s','1h','192.0.2.2',now()-interval '9 days','{}'),('new','s','1h','192.0.2.1',now(),'{}'),('new','s','1h','192.0.2.2',now(),'{}')`,
	} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	installRetentionTestGuard(t, db)
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `SELECT run_id FROM device_inventory_snapshots WHERE run_id='old-a' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	s := &PostgresStore{db: db}
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	n, err := s.DeleteDeviceRetentionBatch(ctx, cutoff, 1)
	if n != 0 || err == nil {
		t.Fatalf("locked eligible candidate must not claim exhaustion: n=%d err=%v", n, err)
	}
	var count int
	if e := db.QueryRowContext(ctx, `SELECT count(*) FROM device_inventory_snapshots`).Scan(&count); e != nil || count != 4 {
		t.Fatal("locked batch changed rows", count, e)
	}
	if err = lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if n, e := s.DeleteDeviceRetentionBatch(ctx, cutoff, 1); n != 1 || e != nil {
			t.Fatal("unlocked retry must progress", n, e)
		}
	}
	if n, e := s.DeleteDeviceRetentionBatch(ctx, cutoff, 1); n != 0 || e != nil {
		t.Fatal("true exhaustion must stay distinguishable", n, e)
	}
}
