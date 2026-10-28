package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is deliberately not the general project test DSN: a dedicated remote
// PostgreSQL test instance is required. Never run this fixture on 184 or on
// the locally disabled PostgreSQL stack.
func identityDerivedReadyTestConfig(t *testing.T) *pgx.ConnConfig {
	t.Helper()
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
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("cannot verify local interface addresses: %v", err)
	}
	local := make([]net.IP, 0, len(interfaces))
	for _, address := range interfaces {
		switch addr := address.(type) {
		case *net.IPNet:
			local = append(local, addr.IP)
		case *net.IPAddr:
			local = append(local, addr.IP)
		}
	}
	for _, address := range resolved {
		if identityReadyForbiddenAddress(address, local) {
			t.Fatal("identity ready fixture resolves to the local host or 184")
		}
	}
	if len(cfg.Fallbacks) > 0 {
		for _, fallback := range cfg.Fallbacks {
			if fallback.Host != cfg.Host {
				t.Fatal("identity ready test DSN must not contain fallback hosts")
			}
		}
	}
	return cfg
}

func identityReadyForbiddenAddress(address net.IP, local []net.IP) bool {
	if address.IsLoopback() || address.IsUnspecified() || address.Equal(net.ParseIP("222.204.3.184")) {
		return true
	}
	for _, localAddress := range local {
		if address.Equal(localAddress) {
			return true
		}
	}
	return false
}

func TestIdentityDerivedReadyTestRejectsLocalInterfaceAndFieldHost(t *testing.T) {
	local := []net.IP{net.ParseIP("192.0.2.9"), net.ParseIP("2001:db8::1")}
	for _, tc := range []struct {
		host      string
		forbidden bool
	}{
		{"127.0.0.1", true}, {"::1", true}, {"0.0.0.0", true},
		{"222.204.3.184", true}, {"192.0.2.9", true}, {"2001:db8::1", true},
		{"192.0.2.10", false},
	} {
		if got := identityReadyForbiddenAddress(net.ParseIP(tc.host), local); got != tc.forbidden {
			t.Errorf("address %s forbidden=%v, want %v", tc.host, got, tc.forbidden)
		}
	}
}

func TestIdentityDerivedReadyProgressCandidate(t *testing.T) {
	cfg := identityDerivedReadyTestConfig(t)
	dsn := cfg.ConnString()
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
	// A deliberate repair of a failed fragment must re-register it even when
	// primary progress has already moved past the fragment.
	if _, err = tx.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='failed' WHERE batch_id='a' AND first_ordinal=1`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_derived_ready WHERE batch_id='a'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed key retained: %d %v", count, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='pending' WHERE batch_id='a' AND first_ordinal=1`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT first_ordinal,priority,accepted_at FROM identity_derived_ready WHERE batch_id='a'`).Scan(&ordinal, &priority, &recorded); err != nil || ordinal != 1 || priority != 1 || !recorded.Equal(accepted) {
		t.Fatalf("repaired fragment was not registered: %d %d %v %v", ordinal, priority, recorded, err)
	}
	// If a repaired key was deferred before primary progress arrived, the
	// progress trigger must wake it as soon as the offset crosses the end.
	if _, err = tx.ExecContext(ctx, `INSERT INTO identity_ingest_batches VALUES('b',2,'fragments',0,'sensor',$1,$1)`, accepted); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO identity_ingest_fragments VALUES('b',0,1,'failed'); UPDATE identity_ingest_fragments SET derived_state='pending' WHERE batch_id='b'; UPDATE identity_derived_ready SET available_at=now()+interval '30 seconds',last_error='identity_ready_not_eligible' WHERE batch_id='b'; UPDATE identity_ingest_batches SET processed_offset=1 WHERE batch_id='b'`); err != nil {
		t.Fatal(err)
	}
	var ready bool
	var lastError string
	if err = tx.QueryRowContext(ctx, `SELECT available_at<=now(),last_error FROM identity_derived_ready WHERE batch_id='b'`).Scan(&ready, &lastError); err != nil || !ready || lastError != "" {
		t.Fatalf("progress did not wake deferred key: ready=%v error=%q err=%v", ready, lastError, err)
	}
}

func TestIdentityDerivedReadyClaimCandidateWithConcurrentOldLease(t *testing.T) {
	cfg := identityDerivedReadyTestConfig(t)
	admin := stdlib.OpenDB(*cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	schema := fmt.Sprintf("identity_ready_claim_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	isolated := cfg.Copy()
	if isolated.RuntimeParams == nil {
		isolated.RuntimeParams = map[string]string{}
	}
	isolated.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*isolated)
	defer func() {
		db.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		admin.Close()
	}()
	_, err := db.ExecContext(ctx, `CREATE TABLE identity_ingest_batches(batch_id text PRIMARY KEY,protocol_version int NOT NULL,payload_format text NOT NULL,processed_offset int NOT NULL,sensor_id text NOT NULL,accepted_at timestamptz,received_at timestamptz NOT NULL,scope_key text NOT NULL,source text NOT NULL,stream_epoch text NOT NULL);
 CREATE TABLE identity_ingest_fragments(batch_id text NOT NULL REFERENCES identity_ingest_batches,first_ordinal int NOT NULL,record_count int NOT NULL CHECK(record_count BETWEEN 1 AND 50),derived_state text NOT NULL,derived_lease_until timestamptz,derived_lease_epoch bigint NOT NULL DEFAULT 0,archive_month text NOT NULL,content_sha256 text NOT NULL,key_scheme text NOT NULL,normalized_events jsonb NOT NULL,PRIMARY KEY(batch_id,first_ordinal));
 CREATE TABLE read_model_runtime_state(name text PRIMARY KEY,state jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now());
 CREATE TABLE identity_materializer_cursors(sensor_id text NOT NULL);
 CREATE TABLE identity_snapshot_projection_jobs(id integer);`)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/identity_derived_ready_candidate.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(fixture)); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	_, err = db.ExecContext(ctx, `INSERT INTO identity_ingest_batches VALUES('a',2,'fragments',0,'sensor',$1,$1,'scope','source','epoch')`, at)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO identity_ingest_fragments(batch_id,first_ordinal,record_count,derived_state,archive_month,content_sha256,key_scheme,normalized_events) VALUES('a',0,1,'pending','202610','hash','source_position_v1','[{}]'),('a',1,1,'pending','202610','hash','source_position_v1','[{}]'); UPDATE identity_ingest_batches SET processed_offset=2 WHERE batch_id='a'`)
	if err != nil {
		t.Fatal(err)
	}
	// Competing scanner instances share one transactional page clock. Even
	// though both start at once, only one may advance a page in this interval.
	scanResults := make(chan identityDerivedReadyPage, 2)
	scanErrors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			page, err := (&PostgresStore{db: db}).scanIdentityDerivedReadyPage(ctx, 1)
			scanResults <- page
			scanErrors <- err
		}()
	}
	var scanned, deferred int
	for i := 0; i < 2; i++ {
		page := <-scanResults
		if err := <-scanErrors; err != nil {
			t.Fatal(err)
		}
		scanned += page.Scanned
		if page.Deferred {
			deferred++
		}
	}
	if scanned != 1 || deferred != 1 {
		t.Fatalf("shared scanner budget bypassed: scanned=%d deferred=%d", scanned, deferred)
	}
	store := &PostgresStore{db: db, sensorID: "sensor"}
	if _, err = db.ExecContext(ctx, `UPDATE identity_derived_ready SET last_error='identity_ready_not_eligible' WHERE batch_id='a' AND first_ordinal=1`); err != nil {
		t.Fatal(err)
	}
	if err = store.publishIdentityDerivedReadyStatus(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `UPDATE read_model_runtime_state SET state=jsonb_set(state,'{sampled_at}',to_jsonb(now()-interval '5 minutes')),updated_at=now() WHERE name='identity-derived-ready:sensor'`)
	if err != nil {
		t.Fatal(err)
	}
	status, err := (&DBStore{pg: store}).IdentityMaterializerStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ready, ok := status["derived_ready"].(map[string]any)
	if !ok || ready["stale"] != true || ready["state"] != "indexing" || ready["index_error_keys_present"] != true {
		t.Fatalf("old sample presented as fresh: %+v", status)
	}
	if err = store.publishIdentityDerivedReadyStatus(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, persistIdentityDerivedReadyStatusSQL, "identity-derived-ready:sensor", `{"state":"ready_index_empty","sampled_at":"2000-01-01T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	var retained string
	if err = db.QueryRowContext(ctx, `SELECT state->>'state' FROM read_model_runtime_state WHERE name='identity-derived-ready:sensor'`).Scan(&retained); err != nil || retained != "indexing" {
		t.Fatalf("older sample overwrote newer status: %q %v", retained, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE identity_derived_ready SET last_error='' WHERE batch_id='a' AND first_ordinal=1`); err != nil {
		t.Fatal(err)
	}

	// A legacy worker owns fragment zero. SKIP LOCKED must allow fragment one
	// through without stealing or changing the first fragment.
	old, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Rollback()
	if _, err = old.ExecContext(ctx, `SELECT 1 FROM identity_ingest_fragments WHERE batch_id='a' AND first_ordinal=0 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	second, err := store.claimIdentityDerivedReady(ctx, 0)
	if err != nil || second.First != 1 || second.DerivedLeaseEpoch != 1 {
		t.Fatalf("skip locked: %+v %v", second, err)
	}
	if err = old.Rollback(); err != nil {
		t.Fatal(err)
	}
	first, err := store.claimIdentityDerivedReady(ctx, 0)
	if err != nil || first.First != 0 || first.DerivedLeaseEpoch != 1 {
		t.Fatalf("first lease: %+v %v", first, err)
	}
	// Simulate lease expiry without changing accepted_at. A new generation
	// fences the old claimant, even if its completion response was delayed.
	_, err = db.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_lease_until=now()-interval '1 second' WHERE batch_id='a' AND first_ordinal=0; UPDATE identity_derived_ready SET available_at=now()-interval '1 second' WHERE batch_id='a' AND first_ordinal=0`)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := store.claimIdentityDerivedReady(ctx, 0)
	if err != nil || replacement.First != 0 || replacement.DerivedLeaseEpoch != 2 || !replacement.Accepted.Equal(at) {
		t.Fatalf("replacement lease: %+v %v", replacement, err)
	}
	result, err := db.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='completed' WHERE batch_id='a' AND first_ordinal=0 AND derived_state='attempted' AND derived_lease_epoch=$1`, first.DerivedLeaseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := result.RowsAffected(); n != 0 {
		t.Fatal("expired claimant committed")
	}
	result, err = db.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='completed' WHERE batch_id='a' AND first_ordinal=0 AND derived_state='attempted' AND derived_lease_epoch=$1`, replacement.DerivedLeaseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		t.Fatal("current claimant could not commit")
	}
	var remaining int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM identity_derived_ready WHERE batch_id='a' AND first_ordinal=0`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("completed key retained: %d %v", remaining, err)
	}
	// Oversized pages must stop at the last consumed key and continue from the
	// next one. These fragments are not yet eligible, so no queue key is added.
	longSensor := strings.Repeat("s", 12*1024)
	_, err = db.ExecContext(ctx, `INSERT INTO identity_ingest_batches VALUES('b',2,'fragments',0,$1,$2,$2,'scope','source','epoch'),('c',2,'fragments',0,$1,$2,$2,'scope','source','epoch')`, longSensor, at)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO identity_ingest_fragments(batch_id,first_ordinal,record_count,derived_state,archive_month,content_sha256,key_scheme,normalized_events) VALUES('b',0,1,'pending','202610','hash','source_position_v1','[{}]'),('c',0,1,'pending','202610','hash','source_position_v1','[{}]'); UPDATE identity_derived_ready_scan SET cursor_batch='a',cursor_ordinal=1,done=false,next_scan_at='-infinity' WHERE id=true`)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.scanIdentityDerivedReadyPage(ctx, 256)
	if err != nil || page.Scanned != 1 || page.Eligible != 0 {
		t.Fatalf("first byte-limited page: %+v %v", page, err)
	}
	var cursor string
	if err = db.QueryRowContext(ctx, `SELECT cursor_batch FROM identity_derived_ready_scan WHERE id=true`).Scan(&cursor); err != nil || cursor != "b" {
		t.Fatalf("first byte-limited cursor=%q err=%v", cursor, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE identity_derived_ready_scan SET next_scan_at='-infinity' WHERE id=true`); err != nil {
		t.Fatal(err)
	}
	page, err = store.scanIdentityDerivedReadyPage(ctx, 256)
	if err != nil || page.Scanned != 1 || page.Eligible != 0 {
		t.Fatalf("second byte-limited page: %+v %v", page, err)
	}
	if err = db.QueryRowContext(ctx, `SELECT cursor_batch FROM identity_derived_ready_scan WHERE id=true`).Scan(&cursor); err != nil || cursor != "c" {
		t.Fatalf("second byte-limited cursor=%q err=%v", cursor, err)
	}
}

func TestIdentityDerivedReadyCandidateStartsWithNonBlockingWriterBarrier(t *testing.T) {
	raw, err := os.ReadFile("testdata/identity_derived_ready_candidate.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	lock := strings.Index(script, "LOCK TABLE identity_ingest_batches, identity_ingest_fragments IN SHARE ROW EXCLUSIVE MODE NOWAIT")
	firstDDL := strings.Index(script, "CREATE TABLE identity_derived_ready")
	if lock < 0 || firstDDL < 0 || lock > firstDDL {
		t.Fatal("candidate must fail immediately if either live writer table is locked before any DDL")
	}
}

func TestIdentityDerivedReadyBarrierFailsFastAndLeavesWriterUnblocked(t *testing.T) {
	cfg := identityDerivedReadyTestConfig(t)
	admin := stdlib.OpenDB(*cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	schema := fmt.Sprintf("identity_ready_barrier_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	isolated := cfg.Copy()
	if isolated.RuntimeParams == nil {
		isolated.RuntimeParams = map[string]string{}
	}
	isolated.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*isolated)
	defer func() {
		db.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		admin.Close()
	}()
	_, err := db.ExecContext(ctx, `CREATE TABLE identity_ingest_batches(batch_id text PRIMARY KEY,protocol_version int NOT NULL,payload_format text NOT NULL,processed_offset int NOT NULL,sensor_id text NOT NULL,accepted_at timestamptz,received_at timestamptz NOT NULL);
 CREATE TABLE identity_ingest_fragments(batch_id text NOT NULL REFERENCES identity_ingest_batches,first_ordinal int NOT NULL,record_count int NOT NULL CHECK(record_count BETWEEN 1 AND 50),derived_state text NOT NULL,PRIMARY KEY(batch_id,first_ordinal));
 INSERT INTO identity_ingest_batches VALUES('a',2,'fragments',0,'sensor',now(),now());
 INSERT INTO identity_ingest_fragments VALUES('a',0,1,'pending'),('a',1,1,'pending');`)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/identity_derived_ready_candidate.sql")
	if err != nil {
		t.Fatal(err)
	}
	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err = writer.ExecContext(ctx, `UPDATE identity_ingest_fragments SET derived_state='attempted' WHERE batch_id='a'`); err != nil {
		t.Fatal(err)
	}
	// The exporter owns the fragment table and may next update the batch. A
	// migration must not hold the batch lock while waiting for this writer.
	attempt, stop := context.WithTimeout(ctx, 2*time.Second)
	_, err = db.ExecContext(attempt, string(fixture))
	stop()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("expected immediate lock-not-available, got %v", err)
	}
	var exists bool
	if err = db.QueryRowContext(ctx, `SELECT to_regclass('identity_derived_ready') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("failed barrier left partial schema: exists=%v err=%v", exists, err)
	}
	progress, stop := context.WithTimeout(ctx, time.Second)
	_, err = db.ExecContext(progress, `UPDATE identity_ingest_batches SET processed_offset=processed_offset WHERE batch_id='a'`)
	stop()
	if err != nil {
		t.Fatalf("failed barrier left batch writer blocked: %v", err)
	}
	if err = writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	// Progress committed before the trigger barrier must be discovered by the
	// pending-key scan; progress committed afterwards must be trigger-enqueued.
	if _, err = db.ExecContext(ctx, `UPDATE identity_ingest_batches SET processed_offset=1 WHERE batch_id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(fixture)); err != nil {
		t.Fatalf("barrier did not recover after writer ended: %v", err)
	}
	page, err := (&PostgresStore{db: db}).scanIdentityDerivedReadyPage(ctx, 256)
	if err != nil || page.Scanned != 2 || page.Eligible != 1 {
		t.Fatalf("pre-barrier pending scan: %+v %v", page, err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE identity_ingest_batches SET processed_offset=2 WHERE batch_id='a'`); err != nil {
		t.Fatal(err)
	}
	var existing, fresh int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE first_ordinal=0 AND priority=1),count(*) FILTER (WHERE first_ordinal=1 AND priority=0) FROM identity_derived_ready WHERE batch_id='a'`).Scan(&existing, &fresh); err != nil || existing != 1 || fresh != 1 {
		t.Fatalf("cutover lost keys: old=%d new=%d err=%v", existing, fresh, err)
	}
}

// The progress trigger inserts a foreign-keyed ready row while the primary
// transaction holds the batch. The exporter completes in the reverse order:
// it updates a fragment and then the batch. Ordinary non-key UPDATE row locks
// must remain compatible with the foreign key check, or this can deadlock.
func TestIdentityDerivedReadyProgressWithConcurrentExportCompletion(t *testing.T) {
	cfg := identityDerivedReadyTestConfig(t)
	admin := stdlib.OpenDB(*cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	schema := fmt.Sprintf("identity_ready_export_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	isolated := cfg.Copy()
	if isolated.RuntimeParams == nil {
		isolated.RuntimeParams = map[string]string{}
	}
	isolated.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*isolated)
	defer func() {
		db.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		admin.Close()
	}()
	_, err := db.ExecContext(ctx, `CREATE TABLE identity_ingest_batches(batch_id text PRIMARY KEY,protocol_version int NOT NULL,payload_format text NOT NULL,processed_offset int NOT NULL,sensor_id text NOT NULL,accepted_at timestamptz,received_at timestamptz NOT NULL,export_marker boolean NOT NULL DEFAULT false);
 CREATE TABLE identity_ingest_fragments(batch_id text NOT NULL REFERENCES identity_ingest_batches,first_ordinal int NOT NULL,record_count int NOT NULL CHECK(record_count BETWEEN 1 AND 50),derived_state text NOT NULL,export_marker boolean NOT NULL DEFAULT false,PRIMARY KEY(batch_id,first_ordinal));
 INSERT INTO identity_ingest_batches(batch_id,protocol_version,payload_format,processed_offset,sensor_id,accepted_at,received_at) VALUES('a',2,'fragments',0,'sensor',now(),now());
 INSERT INTO identity_ingest_fragments(batch_id,first_ordinal,record_count,derived_state) VALUES('a',0,1,'pending');`)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/identity_derived_ready_candidate.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(fixture)); err != nil {
		t.Fatal(err)
	}
	exporter, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Rollback()
	if _, err = exporter.ExecContext(ctx, `UPDATE identity_ingest_fragments SET export_marker=true WHERE batch_id='a' AND first_ordinal=0`); err != nil {
		t.Fatal(err)
	}
	// The progress transaction must finish while the exporter still owns its
	// fragment UPDATE lock; a timeout is a failure, not evidence of safety.
	progress, stop := context.WithTimeout(ctx, 2*time.Second)
	_, err = db.ExecContext(progress, `UPDATE identity_ingest_batches SET processed_offset=1 WHERE batch_id='a'`)
	stop()
	if err != nil {
		t.Fatalf("progress trigger waited for non-key export update: %v", err)
	}
	if _, err = exporter.ExecContext(ctx, `UPDATE identity_ingest_batches SET export_marker=true WHERE batch_id='a'`); err != nil {
		t.Fatal(err)
	}
	if err = exporter.Commit(); err != nil {
		t.Fatal(err)
	}
	var pending, progressDone, exported bool
	if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_derived_ready WHERE batch_id='a' AND first_ordinal=0),processed_offset=1,export_marker FROM identity_ingest_batches WHERE batch_id='a'`).Scan(&pending, &progressDone, &exported); err != nil || !pending || !progressDone || !exported {
		t.Fatalf("concurrent progress/export: pending=%v progress=%v export=%v err=%v", pending, progressDone, exported, err)
	}
}
