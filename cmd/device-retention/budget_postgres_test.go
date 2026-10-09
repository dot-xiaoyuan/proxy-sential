package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestRetentionBudgetPostgresCancelsSlowDelete(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(acceptance|ieee_lease)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("this replay creates relations and requires an owned isolated database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	for _, q := range []string{
		`CREATE TABLE risk_cases(ip inet)`,
		`CREATE TABLE risk_case_evidence_snapshots(evidence jsonb)`,
		`CREATE TABLE device_inventory_snapshots(run_id text,sensor_id text,"window" text,ip inet,created_at timestamptz,inventory jsonb NOT NULL DEFAULT '{}')`,
		`INSERT INTO device_inventory_snapshots VALUES ('old','fixture','1h','192.0.2.200',now()-interval '10 days','{}'),('new','fixture','1h','192.0.2.200',now(),'{}')`,
	} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	guard, err := os.ReadFile("../../migrations/postgres/024_device_retention_reference_guard.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(guard)); err != nil {
		t.Fatal(err)
	}
	// A database-side slow DELETE exercises pgx cancellation and rollback. The
	// fixture is tiny; timeout is caused by this trigger, not production load.
	if _, err = db.ExecContext(ctx, `CREATE FUNCTION slow_retention_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(10); RETURN OLD; END; $$; CREATE TRIGGER slow_retention BEFORE DELETE ON device_inventory_snapshots FOR EACH ROW EXECUTE FUNCTION slow_retention_fixture();`); err != nil {
		t.Fatal(err)
	}
	s, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out bytes.Buffer
	err = maintainRetention(ctx, s, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: 2 * time.Second}, json.NewEncoder(&out), realRetentionClock())
	if err != nil || !strings.Contains(out.String(), `"phase":"batch"`) || !strings.Contains(out.String(), `"batch_outcome_unconfirmed":true`) || !strings.Contains(out.String(), `"deleted_rows":0`) {
		t.Fatalf("database cancellation must stop on budget without claiming the uncommitted DELETE: %v\n%s", err, out.String())
	}
	var rows int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM device_inventory_snapshots`).Scan(&rows); err != nil || rows != 2 {
		t.Fatal("cancelled deletion was not rolled back", rows, err)
	}
	if _, err = db.ExecContext(ctx, `DROP TRIGGER slow_retention ON device_inventory_snapshots`); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err = maintainRetention(ctx, s, retentionOptions{apply: true, batches: 1, batchSize: 500, maxDuration: 10 * time.Second}, json.NewEncoder(&out), realRetentionClock()); err != nil || !strings.Contains(out.String(), `"deleted_rows":1`) || !strings.Contains(out.String(), `"reason":"batch_limit_reached"`) {
		t.Fatal("next invocation did not resume eligible work", err, out.String())
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM device_inventory_snapshots WHERE run_id='new'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatal("latest snapshot must remain protected", rows, err)
	}
}
