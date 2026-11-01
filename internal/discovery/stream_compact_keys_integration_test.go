package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Exercises the actual migration and case trigger only on an explicitly
// configured dedicated remote test instance. Local stacks and 184 are excluded.
func TestCompactEventKeyMigrationRejectsSplitLedgerCaseEvidence(t *testing.T) {
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
	if host == "" || host == "localhost" || host == "222.204.3.184" || host == "192.168.0.30" || strings.HasPrefix(host, "/") || (ip != nil && ip.IsLoopback()) {
		t.Fatal("compact migration replay requires a dedicated remote test host")
	}
	resolved, err := net.LookupIP(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range resolved {
		if address.IsLoopback() || address.Equal(net.ParseIP("222.204.3.184")) || address.Equal(net.ParseIP("192.168.0.30")) {
			t.Fatal("compact migration replay resolves to a protected host")
		}
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback.Host != cfg.Host {
			t.Fatal("compact migration replay DSN must not contain fallback hosts")
		}
	}
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	schema := fmt.Sprintf("compact_keys_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop compact test schema: %v", err)
		}
	}()
	isolated := cfg.Copy()
	if isolated.RuntimeParams == nil {
		isolated.RuntimeParams = map[string]string{}
	}
	isolated.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*isolated)
	defer db.Close()
	_, err = db.ExecContext(ctx, `CREATE TABLE stream_discovery_event_keys (
 epoch text NOT NULL,scope_id text NOT NULL,event_key text NOT NULL,content_sha256 text NOT NULL,
 accepted_month date NOT NULL,first_accepted_at timestamptz NOT NULL,PRIMARY KEY(epoch,scope_id,event_key));
 CREATE TABLE stream_discovery_receipts (
 accepted_month date NOT NULL,epoch text NOT NULL,scope_id text NOT NULL,event_key text NOT NULL,
 content_sha256 text NOT NULL,archive_state text NOT NULL,body_ref jsonb NOT NULL,
 PRIMARY KEY(accepted_month,epoch,scope_id,event_key));
 CREATE TABLE stream_discovery_case_evidence (
 case_id text NOT NULL,epoch text NOT NULL,scope_id text NOT NULL,event_key text NOT NULL,
 content_sha256 text NOT NULL,body_ref jsonb NOT NULL,document text NOT NULL,
 PRIMARY KEY(case_id,epoch,scope_id,event_key));
 CREATE TABLE stream_discovery_changes (epoch text,event_key text,protected boolean);
 CREATE TABLE risk_case_evidence_snapshots (case_id text,evidence jsonb);`)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../migrations/postgres/214_stream_discovery_compact_event_keys.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(migration)); err != nil {
		t.Fatalf("apply compact migration: %v", err)
	}
	_, err = db.ExecContext(ctx, `CREATE TRIGGER protect_stream_discovery_case_evidence
 AFTER INSERT OR UPDATE OF evidence ON risk_case_evidence_snapshots
 FOR EACH ROW EXECUTE FUNCTION sentinel_protect_stream_discovery_case_evidence()`)
	if err != nil {
		t.Fatal(err)
	}
	const epoch, scope, key, month = "fresh", "scope-a", "fresh:stream2-fixed", "2026-11-01"
	hash := sha256.Sum256([]byte("{}"))
	contentHash := hex.EncodeToString(hash[:])
	ref := map[string]string{"class": "evidence", "epoch": epoch, "scope": scope, "key": key, "month": "202611", "sha256": contentHash}
	refJSON, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	snapshotJSON, err := json.Marshal(map[string]any{"stream_discovery_evidence_refs": []any{ref}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_event_keys VALUES($1,$2,$3,$4,$5,now())`, epoch, scope, key, contentHash, month); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_event_keys_compact VALUES(sentinel_stream_discovery_key_hash($1,$2,$3),$1,$2,$3,$4,$5,now())`, epoch, scope, key, contentHash, month); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_receipts VALUES($5,$1,$2,$3,$4,'confirmed',$6)`, epoch, scope, key, contentHash, month, refJSON); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_case_evidence VALUES('case-a',$1,$2,$3,$4,$5,'{}')`, epoch, scope, key, contentHash, refJSON); err != nil {
		t.Fatal(err)
	}
	insertCase := func() error {
		_, err := db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(case_id,evidence) VALUES('case-a',$1)`, snapshotJSON)
		return err
	}
	if err := insertCase(); err != nil {
		t.Fatalf("matching dual ledger rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_discovery_event_keys_compact SET content_sha256='different' WHERE epoch=$1 AND scope_id=$2 AND event_key=$3`, epoch, scope, key); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err == nil {
		t.Fatal("split content hashes authorized a case")
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_discovery_event_keys_compact SET content_sha256=$4,accepted_month='2026-12-01' WHERE epoch=$1 AND scope_id=$2 AND event_key=$3`, epoch, scope, key, contentHash); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err == nil {
		t.Fatal("split receipt months authorized a case")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM stream_discovery_event_keys WHERE epoch=$1 AND scope_id=$2 AND event_key=$3`, epoch, scope, key); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_discovery_event_keys_compact SET accepted_month=$4 WHERE epoch=$1 AND scope_id=$2 AND event_key=$3`, epoch, scope, key, month); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err != nil {
		t.Fatalf("compact-only evidence rejected: %v", err)
	}
}
