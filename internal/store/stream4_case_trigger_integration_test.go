package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"proxy-sentinel/internal/streamlog"
)

// Uses only a dedicated disposable loopback database, including a forwarded
// test instance. It applies PG225, PG247 and PG248 in an isolated schema.
func TestStream4CaseTriggerAndMigrationPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_STREAM4_CASE_DSN")
	if dsn == "" {
		t.Skip("dedicated stream4 case PostgreSQL is not configured")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.Database, "_stream4_case_test") ||
		cfg.Host != "127.0.0.1" && cfg.Host != "::1" || cfg.Port <= 1024 || cfg.Port == 5432 || len(cfg.Fallbacks) > 0 {
		t.Fatal("stream4 migration replay requires a dedicated loopback test database on a nonstandard port")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := fmt.Sprintf("stream4_case_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop stream4 test schema: %v", err)
		}
	}()
	isolated := cfg.Copy()
	if isolated.RuntimeParams == nil {
		isolated.RuntimeParams = map[string]string{}
	}
	isolated.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*isolated)
	defer db.Close()
	_, err = db.ExecContext(ctx, `CREATE TABLE stream_projection_segments (
 segment_id text PRIMARY KEY,epoch text,source_kind text,source_path text,content_sha256 text,archive_receipt_mode text,
 event_count integer,accepted_at timestamptz,projected_at timestamptz,lanes_finalized_at timestamptz,
 source_file_id text,source_start_offset bigint,source_end_offset bigint);
 CREATE TABLE stream_discovery_segment_receipt_manifests (
 segment_id text PRIMARY KEY,archive_month text,body_layout text,results jsonb);
 CREATE TABLE stream_discovery_event_keys (
 epoch text,scope_id text,event_key text,content_sha256 text,accepted_month date,first_accepted_at timestamptz);
 CREATE TABLE stream_discovery_event_keys_compact (
 key_hash bytea,epoch text,scope_id text,event_key text,content_sha256 text,
 accepted_month date,receipt_segment_id text,receipt_ordinal integer);
 CREATE TABLE stream_discovery_receipts (
 accepted_month date,epoch text,scope_id text,event_key text,content_sha256 text,
 result text,accepted_at timestamptz,archive_state text,body_ref jsonb,archive_segment_id text);
 CREATE TABLE stream_discovery_case_evidence (
 case_id text,epoch text,scope_id text,event_key text,content_sha256 text,body_ref jsonb,document text);
 CREATE TABLE stream_discovery_changes (epoch text,event_key text,protected boolean);
 CREATE TABLE risk_case_evidence_snapshots (case_id text,evidence jsonb);
 CREATE FUNCTION sentinel_stream_discovery_key_hash(epoch text,scope_id text,event_key text)
 RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT sha256(convert_to(jsonb_build_array(epoch,scope_id,event_key)::text,'UTF8'))
 $$;`)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"225_passive_segment_key_locator.sql", "247_device_signal_manifest_receipts.sql", "248_device_signal_segment_keys.sql"} {
		migration, err := os.ReadFile("../../migrations/postgres/" + name)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(migration)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("apply %s: %v", name, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER protect_stream_discovery_case_evidence
 AFTER INSERT OR UPDATE OF evidence ON risk_case_evidence_snapshots
 FOR EACH ROW EXECUTE FUNCTION sentinel_protect_stream_discovery_case_evidence()`); err != nil {
		t.Fatal(err)
	}
	const epoch, scope, path, file = "fresh", "scope-a", "/signals/device.jsonl", "file-a"
	id := streamlog.SourceSegmentID(streamlog.Segment{Epoch: epoch, Source: "device-signals", SourcePath: path,
		FileID: file, StartOffset: 0, EndOffset: 100, SourceGeneration: 7})
	var sqlID string
	if err := db.QueryRowContext(ctx, `SELECT sentinel_stream_source_segment_id($1,'device-signals',$2,$3,0,100,7)`, epoch, path, file).Scan(&sqlID); err != nil || sqlID != id {
		t.Fatalf("journal and SQL segment IDs disagree: %s %s %v", id, sqlID, err)
	}
	key := epoch + ":stream4-" + id + "-0"
	var parsedID string
	var ordinal int
	if err := db.QueryRowContext(ctx, `SELECT segment_id,ordinal FROM sentinel_device_stream4_locator($1,$2)`, epoch, key).Scan(&parsedID, &ordinal); err != nil || parsedID != id || ordinal != 0 {
		t.Fatalf("canonical key rejected: %s %d %v", parsedID, ordinal, err)
	}
	var invalid int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sentinel_device_stream4_locator($1,$2)`, epoch, key+"0").Scan(&invalid); err != nil || invalid != 0 {
		t.Fatal("noncanonical key accepted")
	}
	accepted := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	body := "{}"
	sum := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(sum[:])
	ref := map[string]string{"class": "evidence", "epoch": epoch, "scope": scope, "key": key, "month": "202611", "sha256": hash}
	refJSON, _ := json.Marshal(ref)
	snapshotJSON, _ := json.Marshal(map[string]any{"stream_discovery_evidence_refs": []any{ref}})
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_projection_segments
 (segment_id,epoch,source_kind,source_path,archive_receipt_mode,event_count,accepted_at,projected_at,
 source_file_id,source_start_offset,source_end_offset,passive_key_scheme,source_generation)
 VALUES($1,$2,'device-signals',$3,'manifest',1,$4,$4,$5,0,100,'stream4',7)`, id, epoch, path, accepted, file); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_segment_receipt_manifests
 (segment_id,archive_month,body_layout,results,key_scheme,scope_id,content_hashes)
 VALUES($1,'202611','','["applied"]'::jsonb,'stream4',$2,$3)`, id, scope, sum[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_case_evidence
 (case_id,epoch,scope_id,event_key,content_sha256,body_ref,document)
 VALUES('case-a',$1,$2,$3,$4,$5,$6)`, epoch, scope, key, hash, refJSON, body); err != nil {
		t.Fatal(err)
	}
	insertCase := func() error {
		_, err := db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(case_id,evidence) VALUES('case-a',$1)`, snapshotJSON)
		return err
	}
	if err := insertCase(); err == nil {
		t.Fatal("pending cross-database archive authorized a case")
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_projection_segments SET lanes_finalized_at=$2 WHERE segment_id=$1`, id, accepted.Add(time.Second)); err != nil {
		t.Fatalf("finalization transition failed: %v", err)
	}
	if err := insertCase(); err != nil {
		t.Fatalf("finalized stream4 case rejected: %v", err)
	}
	for _, query := range []string{
		`UPDATE stream_projection_segments SET source_end_offset=101 WHERE segment_id=$1`,
		`UPDATE stream_projection_segments SET lanes_finalized_at=NULL WHERE segment_id=$1`,
		`UPDATE stream_discovery_segment_receipt_manifests SET content_hashes=decode('00','hex') WHERE segment_id=$1`,
		`DELETE FROM stream_discovery_segment_receipt_manifests WHERE segment_id=$1`,
		`DELETE FROM stream_projection_segments WHERE segment_id=$1`,
	} {
		if _, err := db.ExecContext(ctx, query, id); err == nil {
			t.Errorf("immutable stream4 proof changed: %s", query)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_receipts
 (accepted_month,epoch,scope_id,event_key,content_sha256,result,accepted_at,archive_state,body_ref,archive_segment_id)
 VALUES('2026-11-01',$1,$2,$3,$4,'applied',$5,'failed',$6,$7)`, epoch, scope, key, hash, accepted, refJSON, id); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err == nil {
		t.Fatal("failed diagnostic overrode immutable manifest")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM stream_discovery_receipts WHERE event_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_event_keys
 (epoch,scope_id,event_key,content_sha256,accepted_month) VALUES($1,$2,$3,$4,'2026-11-01')`, epoch, scope, key, hash); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err == nil {
		t.Fatal("legacy key collision authorized stream4 case")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM stream_discovery_event_keys WHERE event_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err != nil {
		t.Fatalf("conflict cleanup did not restore proof: %v", err)
	}
	if _, err := db.ExecContext(ctx, `TRUNCATE stream_discovery_segment_receipt_manifests`); err == nil {
		t.Fatal("stream4 manifest was truncated")
	}
}
