package store

import (
	"bytes"
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

// Run only against a dedicated disposable loopback PostgreSQL database on a
// nonstandard port. The fixture applies the actual forward migration and
// executes its case trigger; it never connects to 184 or a snapshot stack.
func TestStream3CaseTriggerProtectsSegmentOriginalPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_STREAM3_CASE_DSN")
	if dsn == "" {
		t.Skip("dedicated disposable stream3 PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.Database, "_stream3_case_test") ||
		(cfg.Host != "127.0.0.1" && cfg.Host != "::1") ||
		cfg.Port <= 1024 || cfg.Port == 5432 || len(cfg.Fallbacks) > 0 {
		t.Fatal("stream3 trigger replay requires a dedicated loopback test database on a nonstandard port")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := fmt.Sprintf("stream3_case_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("drop stream3 test schema: %v", err)
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
 epoch text,scope_id text,event_key text,content_sha256 text,accepted_month date);
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
	migration, err := os.ReadFile("../../migrations/postgres/225_passive_segment_key_locator.sql")
	if err != nil {
		t.Fatal(err)
	}
	// An interrupted migration must leave neither columns nor a locator behind.
	interrupted, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := interrupted.ExecContext(ctx, string(migration)); err != nil {
		_ = interrupted.Rollback()
		t.Fatalf("apply interrupted stream3 migration: %v", err)
	}
	if err := interrupted.Rollback(); err != nil {
		t.Fatal(err)
	}
	var partialMigration bool
	if err := db.QueryRowContext(ctx, `SELECT
	 EXISTS(SELECT 1 FROM information_schema.columns
	  WHERE table_schema=current_schema() AND table_name='stream_projection_segments'
	   AND column_name='passive_key_scheme')
	 OR to_regprocedure('sentinel_stream3_locator(text,text)') IS NOT NULL`).Scan(&partialMigration); err != nil {
		t.Fatal(err)
	}
	if partialMigration {
		t.Fatal("rolled-back stream3 migration left partial schema")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, string(migration)); err != nil {
		_ = tx.Rollback()
		t.Fatalf("apply stream3 migration: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER protect_stream_discovery_case_evidence
 AFTER INSERT OR UPDATE OF evidence ON risk_case_evidence_snapshots
 FOR EACH ROW EXECUTE FUNCTION sentinel_protect_stream_discovery_case_evidence()`); err != nil {
		t.Fatal(err)
	}
	const epoch, scope, path, file = "fresh", "scope-a", "packet://test", "capture-a"
	id := streamlog.SourceSegmentID(streamlog.Segment{Epoch: epoch, Source: "passive-discovery", SourcePath: path,
		FileID: file, StartOffset: 0, EndOffset: 100})
	var sqlID string
	if err := db.QueryRowContext(ctx, `SELECT sentinel_stream_source_segment_id($1,'passive-discovery',$2,$3,0,100,0)`, epoch, path, file).Scan(&sqlID); err != nil || sqlID != id {
		t.Fatalf("SQL source ID differs from journal: sql=%s journal=%s err=%v", sqlID, id, err)
	}
	generatedID := streamlog.SourceSegmentID(streamlog.Segment{Epoch: epoch, Source: "passive-discovery", SourcePath: path,
		FileID: file, StartOffset: 0, EndOffset: 100, SourceGeneration: 7})
	if err := db.QueryRowContext(ctx, `SELECT sentinel_stream_source_segment_id($1,'passive-discovery',$2,$3,0,100,7)`, epoch, path, file).Scan(&sqlID); err != nil || sqlID != generatedID {
		t.Fatalf("SQL generated source ID differs from journal: sql=%s journal=%s err=%v", sqlID, generatedID, err)
	}
	key := epoch + ":stream3-" + id + "-0"
	var parsedID string
	var ordinal int
	if err := db.QueryRowContext(ctx, `SELECT segment_id,ordinal FROM sentinel_stream3_locator($1,$2)`, epoch, key).Scan(&parsedID, &ordinal); err != nil || parsedID != id || ordinal != 0 {
		t.Fatalf("canonical stream3 key rejected: id=%s ordinal=%d err=%v", parsedID, ordinal, err)
	}
	var invalidCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sentinel_stream3_locator($1,$2)`, epoch, epoch+":stream3-"+id+"-00").Scan(&invalidCount); err != nil || invalidCount != 0 {
		t.Fatalf("noncanonical stream3 key accepted: count=%d err=%v", invalidCount, err)
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
 lanes_finalized_at,source_file_id,source_start_offset,source_end_offset,passive_key_scheme,source_generation)
 VALUES($1,$2,'passive-discovery',$3,'manifest',1,$4,$4,$4,$5,0,100,'stream3',0)`, id, epoch, path, accepted, file); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_segment_receipt_manifests
 (segment_id,archive_month,body_layout,results,key_scheme,scope_id,content_hashes)
 VALUES($1,'202611','','["applied"]'::jsonb,'stream3',$2,$3)`, id, scope, sum[:]); err != nil {
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
	if err := insertCase(); err != nil {
		t.Fatalf("valid finalized stream3 case rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_receipts
 (accepted_month,epoch,scope_id,event_key,content_sha256,result,accepted_at,archive_state,body_ref,archive_segment_id)
 VALUES('2026-11-01',$1,$2,$3,$4,'applied',$5,'segment',$6::jsonb,$7)`, epoch, scope, key, hash, accepted, string(refJSON), id); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err != nil {
		t.Fatalf("matching auxiliary stream3 diagnostic receipt rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_discovery_receipts SET accepted_at=$2 WHERE event_key=$1`, key, accepted.Add(time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err != nil {
		t.Fatalf("PostgreSQL-rounded stream3 diagnostic acceptance rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_discovery_receipts SET accepted_at=$2 WHERE event_key=$1`, key, accepted); err != nil {
		t.Fatal(err)
	}
	wrongRef := map[string]string{"class": "evidence", "epoch": epoch, "scope": scope,
		"key": key, "month": "202611", "sha256": strings.Repeat("0", 64)}
	wrongRefJSON, _ := json.Marshal(wrongRef)
	for _, tc := range []struct {
		name, column string
		bad, good    any
	}{
		{"archive failed", "archive_state", "failed", "segment"},
		{"hash conflict", "content_sha256", strings.Repeat("0", 64), hash},
		{"reference conflict", "body_ref", string(wrongRefJSON), string(refJSON)},
		{"result conflict", "result", "changed", "applied"},
		{"segment locator conflict", "archive_segment_id", "other-segment", id},
		{"acceptance time conflict", "accepted_at", accepted.Add(time.Second), accepted},
	} {
		query := `UPDATE stream_discovery_receipts SET ` + tc.column + `=$2 WHERE event_key=$1`
		result, err := db.ExecContext(ctx, query, key, tc.bad)
		if err != nil {
			t.Fatalf("set %s diagnostic contradiction: %v", tc.name, err)
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			t.Fatalf("set %s diagnostic contradiction affected %d rows: %v", tc.name, changed, err)
		}
		if err := insertCase(); err == nil {
			t.Errorf("%s diagnostic contradiction authorized stream3 case", tc.name)
		}
		if _, err := db.ExecContext(ctx, query, key, tc.good); err != nil {
			t.Fatalf("restore %s diagnostic receipt: %v", tc.name, err)
		}
	}
	if err := insertCase(); err != nil {
		t.Fatalf("restored auxiliary stream3 diagnostic receipt rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_event_keys
 (epoch,scope_id,event_key,content_sha256,accepted_month) VALUES($1,$2,$3,$4,'2026-11-01')`, epoch, scope, key, hash); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err == nil {
		t.Fatal("ambiguous old and stream3 identities authorized a case")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM stream_discovery_event_keys WHERE event_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	wrongHash := bytes.Repeat([]byte{0x44}, 32)
	for _, tc := range []struct {
		name  string
		query string
		args  []any
	}{
		{"segment scheme", `UPDATE stream_projection_segments SET passive_key_scheme='legacy' WHERE segment_id=$1`, []any{id}},
		{"segment generation", `UPDATE stream_projection_segments SET source_generation=1 WHERE segment_id=$1`, []any{id}},
		{"segment epoch", `UPDATE stream_projection_segments SET epoch='other' WHERE segment_id=$1`, []any{id}},
		{"segment source", `UPDATE stream_projection_segments SET source_kind='other' WHERE segment_id=$1`, []any{id}},
		{"segment path", `UPDATE stream_projection_segments SET source_path='other' WHERE segment_id=$1`, []any{id}},
		{"segment file", `UPDATE stream_projection_segments SET source_file_id='other' WHERE segment_id=$1`, []any{id}},
		{"segment position", `UPDATE stream_projection_segments SET source_end_offset=101 WHERE segment_id=$1`, []any{id}},
		{"segment hash", `UPDATE stream_projection_segments SET content_sha256='changed' WHERE segment_id=$1`, []any{id}},
		{"segment accepted", `UPDATE stream_projection_segments SET accepted_at=accepted_at+interval '1 second' WHERE segment_id=$1`, []any{id}},
		{"segment count", `UPDATE stream_projection_segments SET event_count=2 WHERE segment_id=$1`, []any{id}},
		{"segment mode", `UPDATE stream_projection_segments SET archive_receipt_mode='event' WHERE segment_id=$1`, []any{id}},
		{"segment finalized withdrawal", `UPDATE stream_projection_segments SET lanes_finalized_at=NULL WHERE segment_id=$1`, []any{id}},
		{"segment finalized replacement", `UPDATE stream_projection_segments SET lanes_finalized_at=lanes_finalized_at+interval '1 second' WHERE segment_id=$1`, []any{id}},
		{"segment deletion", `DELETE FROM stream_projection_segments WHERE segment_id=$1`, []any{id}},
		{"manifest hash", `UPDATE stream_discovery_segment_receipt_manifests SET content_hashes=$2 WHERE segment_id=$1`, []any{id, wrongHash}},
		{"manifest result", `UPDATE stream_discovery_segment_receipt_manifests SET results='["changed"]'::jsonb WHERE segment_id=$1`, []any{id}},
		{"manifest scope", `UPDATE stream_discovery_segment_receipt_manifests SET scope_id='other' WHERE segment_id=$1`, []any{id}},
		{"manifest scheme", `UPDATE stream_discovery_segment_receipt_manifests SET key_scheme='stream2' WHERE segment_id=$1`, []any{id}},
		{"manifest deletion", `DELETE FROM stream_discovery_segment_receipt_manifests WHERE segment_id=$1`, []any{id}},
	} {
		if _, err := db.ExecContext(ctx, tc.query, tc.args...); err == nil {
			t.Errorf("stream3 %s mutation was accepted", tc.name)
		}
	}
	if err := insertCase(); err != nil {
		t.Fatalf("rejected metadata mutations changed the valid case: %v", err)
	}
	pendingFile := "capture-finalize-pending"
	pendingID := streamlog.SourceSegmentID(streamlog.Segment{Epoch: epoch, Source: "passive-discovery", SourcePath: path,
		FileID: pendingFile, StartOffset: 0, EndOffset: 100})
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_projection_segments
 (segment_id,epoch,source_kind,source_path,archive_receipt_mode,event_count,accepted_at,projected_at,
 lanes_finalized_at,source_file_id,source_start_offset,source_end_offset,passive_key_scheme,source_generation)
 VALUES($1,$2,'passive-discovery',$3,'manifest',1,$4,$4,NULL,$5,0,100,'stream3',0)`, pendingID, epoch, path, accepted, pendingFile); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_projection_segments SET lanes_finalized_at=$2 WHERE segment_id=$1`, pendingID, accepted); err != nil {
		t.Fatalf("normal stream3 finalization rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_projection_segments SET lanes_finalized_at=NULL WHERE segment_id=$1`, pendingID); err == nil {
		t.Fatal("stream3 finalization could be withdrawn")
	}
	for _, tc := range []struct {
		label     string
		end       int64
		finalized bool
		hashes    []byte
	}{
		{"wrong-hash", 100, true, wrongHash},
		{"pending", 100, false, sum[:]},
		{"wrong-position", 101, true, sum[:]},
	} {
		fileID := "capture-" + tc.label
		caseID := "case-" + tc.label
		segmentID := streamlog.SourceSegmentID(streamlog.Segment{Epoch: epoch, Source: "passive-discovery", SourcePath: path,
			FileID: fileID, StartOffset: 0, EndOffset: 100})
		badKey := epoch + ":stream3-" + segmentID + "-0"
		badRef := map[string]string{"class": "evidence", "epoch": epoch, "scope": scope, "key": badKey, "month": "202611", "sha256": hash}
		badRefJSON, _ := json.Marshal(badRef)
		badSnapshotJSON, _ := json.Marshal(map[string]any{"stream_discovery_evidence_refs": []any{badRef}})
		var finalization any
		if tc.finalized {
			finalization = accepted
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO stream_projection_segments
 (segment_id,epoch,source_kind,source_path,archive_receipt_mode,event_count,accepted_at,projected_at,
 lanes_finalized_at,source_file_id,source_start_offset,source_end_offset,passive_key_scheme,source_generation)
 VALUES($1,$2,'passive-discovery',$3,'manifest',1,$4,$4,$5,$6,0,$7,'stream3',0)`, segmentID, epoch, path, accepted, finalization, fileID, tc.end); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_segment_receipt_manifests
 (segment_id,archive_month,body_layout,results,key_scheme,scope_id,content_hashes)
 VALUES($1,'202611','','["applied"]'::jsonb,'stream3',$2,$3)`, segmentID, scope, tc.hashes); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_case_evidence
 (case_id,epoch,scope_id,event_key,content_sha256,body_ref,document)
 VALUES($1,$2,$3,$4,$5,$6,$7)`, caseID, epoch, scope, badKey, hash, badRefJSON, body); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(case_id,evidence) VALUES($1,$2)`, caseID, badSnapshotJSON); err == nil {
			t.Errorf("%s stream3 metadata authorized a case", tc.label)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_discovery_case_evidence SET document='{"changed":true}' WHERE case_id='case-a'`); err != nil {
		t.Fatal(err)
	}
	if err := insertCase(); err == nil {
		t.Fatal("changed saved original authorized a case")
	}
	// The newly replaced trigger still accepts the old per-event path.
	oldKey := epoch + ":stream2-existing"
	oldRef := map[string]string{"class": "evidence", "epoch": epoch, "scope": scope, "key": oldKey, "month": "202611", "sha256": hash}
	oldRefJSON, _ := json.Marshal(oldRef)
	oldSnapshotJSON, _ := json.Marshal(map[string]any{"stream_discovery_evidence_refs": []any{oldRef}})
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_event_keys
 (epoch,scope_id,event_key,content_sha256,accepted_month) VALUES($1,$2,$3,$4,'2026-11-01')`, epoch, scope, oldKey, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_receipts
 (accepted_month,epoch,scope_id,event_key,content_sha256,archive_state,body_ref,archive_segment_id)
 VALUES('2026-11-01',$1,$2,$3,$4,'confirmed',$5,NULL)`, epoch, scope, oldKey, hash, oldRefJSON); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_case_evidence
 (case_id,epoch,scope_id,event_key,content_sha256,body_ref,document)
 VALUES('case-a',$1,$2,$3,$4,$5,$6)`, epoch, scope, oldKey, hash, oldRefJSON, body); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(case_id,evidence) VALUES('case-a',$1)`, oldSnapshotJSON); err != nil {
		t.Fatalf("old stream2 case path changed: %v", err)
	}
	// The new guards must leave older rows' DML behavior intact.
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_projection_segments
 (segment_id,epoch,source_kind,source_path,archive_receipt_mode,event_count,accepted_at,projected_at)
 VALUES('legacy-segment',$1,'passive-discovery',$2,'manifest',1,$3,$3)`, epoch, path, accepted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_discovery_segment_receipt_manifests
 (segment_id,archive_month,body_layout,results) VALUES('legacy-segment','202611','','["applied"]'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE stream_projection_segments SET source_path='legacy-changed' WHERE segment_id='legacy-segment'`,
		`UPDATE stream_discovery_segment_receipt_manifests SET results='["updated"]'::jsonb WHERE segment_id='legacy-segment'`,
		`DELETE FROM stream_discovery_segment_receipt_manifests WHERE segment_id='legacy-segment'`,
		`DELETE FROM stream_projection_segments WHERE segment_id='legacy-segment'`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatalf("legacy metadata mutation changed: %v", err)
		}
	}
}
