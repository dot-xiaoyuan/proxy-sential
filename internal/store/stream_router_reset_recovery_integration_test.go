package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Runs only against a disposable owned PostgreSQL database. It executes the
// real migration, including the FK and statement trigger used by broad resets.
func TestStreamRouterResetAuditMigrationPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	schema := fmt.Sprintf("stream_router_reset_audit_%d", time.Now().UnixNano())
	if _, err = db.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	if _, err = db.ExecContext(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE stream_router_fresh_cutovers (
sensor_id text NOT NULL,cancel_id text NOT NULL,indexed_after timestamptz NOT NULL,
PRIMARY KEY(sensor_id,indexed_after));
CREATE TABLE stream_router_recognition_state (
sensor_id text PRIMARY KEY,fresh_cutoff_at timestamptz,cancel_id text NOT NULL,
cursor_indexed_at timestamptz,processed_events bigint NOT NULL);`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../migrations/postgres/224_stream_router_reset_recovery_audit.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("apply PG224: %v", err)
	}
	fixed := time.Now().UTC().Add(-4 * 24 * time.Hour).Truncate(time.Microsecond)
	reset := fixed.Add(24 * time.Hour)
	first := reset.Add(15 * time.Minute)
	const sensor, cancelID = "reset-test-sensor-a", "reset-test-cancel-a"
	if _, err = db.ExecContext(ctx, `INSERT INTO stream_router_fresh_cutovers(sensor_id,cancel_id,indexed_after) VALUES($1,$2,$3)`, sensor, cancelID, fixed); err != nil {
		t.Fatal(err)
	}
	insertAudit := func(exec interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	}, target, auditCancelID string, at time.Time) error {
		_, insertErr := exec.ExecContext(ctx, `INSERT INTO stream_router_reset_recoveries(
sensor_id,reset_id,fixed_cutover_at,fixed_cancel_id,reset_started_at,first_indexed_at,
first_event_key,first_content_sha256,retained_before_reset_rows,retained_reset_to_first_rows,authorization_ref)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,0,$9)`, target, "reset-1", at, auditCancelID,
			reset, first, "first-key", strings.Repeat("a", 64), "authorized-reset-fixture")
		return insertErr
	}
	if err = insertAudit(db, sensor, cancelID, fixed.Add(time.Hour)); err == nil {
		t.Fatal("audit accepted a cutover not present in immutable history")
	}
	if err = insertAudit(db, sensor, cancelID, fixed); err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"update":         `UPDATE stream_router_reset_recoveries SET authorization_ref='changed' WHERE sensor_id='reset-test-sensor-a'`,
		"delete":         `DELETE FROM stream_router_reset_recoveries WHERE sensor_id='reset-test-sensor-a'`,
		"truncate":       `TRUNCATE stream_router_reset_recoveries`,
		"parent_cascade": `TRUNCATE stream_router_fresh_cutovers CASCADE`,
	} {
		if _, err = db.ExecContext(ctx, statement); err == nil {
			t.Fatalf("%s removed or changed immutable reset audit", name)
		}
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM stream_router_reset_recoveries WHERE sensor_id=$1`, sensor).Scan(&count); err != nil || count != 1 {
		t.Fatalf("immutable audit disappeared after forbidden mutations: count=%d err=%v", count, err)
	}

	const second = "reset-test-sensor-b"
	if _, err = db.ExecContext(ctx, `INSERT INTO stream_router_fresh_cutovers(sensor_id,cancel_id,indexed_after) VALUES($1,$2,$3)`, second, "reset-test-cancel-b", fixed); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = insertAudit(tx, second, "reset-test-cancel-b", fixed); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO stream_router_recognition_state(sensor_id,fresh_cutoff_at,cancel_id,cursor_indexed_at,processed_events)
VALUES($1,$2,$3,$4,0)`, second, fixed, "reset-test-cancel-b", reset); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM stream_router_reset_recoveries WHERE sensor_id=$1`, second).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back audit persisted: count=%d err=%v", count, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM stream_router_recognition_state WHERE sensor_id=$1`, second).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back cursor persisted: count=%d err=%v", count, err)
	}
}
