package store

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This is deliberately not the general project test DSN: a dedicated remote
// PostgreSQL test instance is required. Never run this fixture on 184 or on
// the locally disabled PostgreSQL stack.
func TestIdentityDerivedReadyProgressCandidate(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_IDENTITY_READY_DSN")
	if dsn == "" {
		t.Skip("dedicated remote PostgreSQL test instance required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.ToLower(cfg.Host)
	ip := net.ParseIP(host)
	if host == "" || host == "localhost" || host == "222.204.3.184" || (ip != nil && ip.IsLoopback()) || strings.HasPrefix(host, "/") {
		t.Fatal("identity ready fixture cannot run on the local host or 184")
	}
	resolved, err := net.LookupIP(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range resolved {
		if address.IsLoopback() || address.Equal(net.ParseIP("222.204.3.184")) {
			t.Fatal("identity ready fixture resolves to the local host or 184")
		}
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// A private schema and rollback prevent this replay from touching any
	// existing application table, even in the designated test database.
	schema := fmt.Sprintf("identity_ready_test_%d", time.Now().UnixNano())
	if _, err = tx.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `CREATE TABLE identity_ingest_batches(batch_id text PRIMARY KEY,protocol_version int NOT NULL,payload_format text NOT NULL,processed_offset int NOT NULL,sensor_id text NOT NULL,accepted_at timestamptz,received_at timestamptz NOT NULL);
 CREATE TABLE identity_ingest_fragments(batch_id text NOT NULL REFERENCES identity_ingest_batches,first_ordinal int NOT NULL,record_count int NOT NULL CHECK(record_count BETWEEN 1 AND 50),derived_state text NOT NULL,PRIMARY KEY(batch_id,first_ordinal));`)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/identity_derived_ready_candidate.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, string(fixture)); err != nil {
		t.Fatal(err)
	}
	accepted := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_ingest_batches VALUES('a',2,'fragments',0,'sensor',$1,$1)`, accepted)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_ingest_fragments VALUES('a',0,1,'pending'),('a',1,2,'pending'),('a',3,1,'completed')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_ingest_batches SET processed_offset=2 WHERE batch_id='a'`); err != nil {
		t.Fatal(err)
	}
	var ordinal, priority int
	var recorded time.Time
	if err = tx.QueryRowContext(ctx, `SELECT first_ordinal,priority,accepted_at FROM identity_derived_ready WHERE batch_id='a'`).Scan(&ordinal, &priority, &recorded); err != nil || ordinal != 0 || priority != 0 || !recorded.Equal(accepted) {
		t.Fatalf("first eligible key: %d %d %v %v", ordinal, priority, recorded, err)
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT advance; UPDATE identity_ingest_batches SET processed_offset=3 WHERE batch_id='a'; ROLLBACK TO SAVEPOINT advance`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_derived_ready WHERE batch_id='a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rolled-back progress leaked ready key: %d %v", count, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_ingest_batches SET processed_offset=4 WHERE batch_id='a'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_derived_ready WHERE batch_id='a'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("crossing or completed fragment: %d %v", count, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='completed' WHERE batch_id='a' AND first_ordinal=0`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_derived_ready WHERE batch_id='a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("terminal key was not retired: %d %v", count, err)
	}
}
