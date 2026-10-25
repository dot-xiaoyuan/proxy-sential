package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestVerifyPassiveStreamCutoverRequiresAuditedFreshStart(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cursor := streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: "packet://bond0/passive-node", FileID: "boot-a", Offset: 100, DiscardedBeforeOffset: 0, ParserVersion: "passive-frame-v1", LastSegmentID: "segment-one"}
	mock.ExpectQuery("FROM stream_source_cutovers").WithArgs("fresh-1", "passive-discovery", cursor.Path).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "cancel_manifest_sha256"}).AddRow("node", "boot-a", int64(0), "passive-frame-v1", strings.Repeat("a", 64)))
	if err := verifyPassiveStreamCutover(context.Background(), db, cursor, "node"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePassiveStreamCutoverActivatesOnlyAfterLedgerAndCursor(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spool := t.TempDir()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	source := discovery.Source{ID: "passive-node", Node: "node", Site: "site", Domain: "domain", Address: "bond0"}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "node", CollectorInstanceID: "boot", CampusID: "site", AccessDomain: "domain", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := discovery.PassiveStreamSourcePath(source)
	encoded, _ := json.Marshal(struct {
		Epoch, Source, Path, CancelID string
		Cutoff                        time.Time
		Rows                          []streamDiscardRow
	}{"fresh-1", "passive-discovery", path, "cancel-1", at, []streamDiscardRow{}})
	sum := sha256.Sum256(encoded)
	hash := hex.EncodeToString(sum[:])
	mock.ExpectQuery("SELECT count\\(\\*\\) FROM discovery_batch_work").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(0)))
	mock.ExpectQuery("FROM discovery_cancel_manifest m JOIN ingest_batches b").WithArgs(at).WillReturnRows(sqlmock.NewRows([]string{"cancel_id", "batch_id", "original_lane", "remaining_events", "original_created_at", "checksum", "cutoff_at"}))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO stream_source_cutovers").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FROM stream_source_cutovers WHERE epoch=\\$1").WithArgs("fresh-1", path).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "previous_release", "legacy_cutoff_at", "legacy_cancel_id", "cancel_manifest_sha256", "state"}).AddRow("node", "boot", int64(0), "passive-frame-v1", "compatible-a", at, "cancel-1", hash, "prepared"))
	mock.ExpectCommit()
	mock.ExpectExec("UPDATE stream_source_cutovers SET state='active'").WithArgs("fresh-1", path, hash).WillReturnResult(sqlmock.NewResult(0, 1))
	got, err := preparePassiveStreamCutover(context.Background(), db, j, source, scope, spool, "fresh-1", "cancel-1", "compatible-a", at)
	if err != nil || got != hash {
		t.Fatalf("cutover not activated: %s %v", got, err)
	}
	cursor, err := j.LoadSource("passive-discovery", path)
	if err != nil || cursor.Epoch != "fresh-1" || cursor.Offset != 0 {
		t.Fatalf("fresh source cursor missing: %+v %v", cursor, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCollectPassiveSpoolRowsAuditsUnprocessedOriginals(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("a", 32) + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(`[{"event_id":"old","timestamp":"2026-10-24T10:00:00Z"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := collectPassiveSpoolRows(dir)
	if err != nil || len(rows) != 1 || rows[0].UnprocessedRecords != 1 || rows[0].ContentSHA256 == "" || rows[0].LegacyStatus != "unprocessed" {
		t.Fatalf("spool audit: %+v %v", rows, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".tmp"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := collectPassiveSpoolRows(dir); err == nil {
		t.Fatal("in-flight spool file silently ignored")
	}
	stale := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(filepath.Join(dir, name+".tmp"), stale, stale); err != nil {
		t.Fatal(err)
	}
	rows, err = collectPassiveSpoolRows(dir)
	if err != nil || len(rows) != 2 || rows[1].LegacyStatus != "partial_unknown_count" || rows[1].UnprocessedRecords != 0 || rows[1].UnprocessedBytes == 0 || rows[1].ContentSHA256 == "" {
		t.Fatalf("stale partial spool bytes were not audited: %+v %v", rows, err)
	}
}

func TestLoadCancelledDiscoveryRowsIncludesEarlierCancellation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Truncate(time.Second)
	earlier := cutoff.Add(-time.Hour)
	mock.ExpectQuery("FROM discovery_cancel_manifest m JOIN ingest_batches b").WithArgs(cutoff).WillReturnRows(
		sqlmock.NewRows([]string{"cancel_id", "batch_id", "original_lane", "remaining_events", "original_created_at", "checksum", "cutoff_at"}).
			AddRow("older-cancel", "batch-1", "realtime", 17, earlier, strings.Repeat("a", 64), earlier).
			AddRow("new-cancel", "batch-2", "backfill", 4, cutoff, strings.Repeat("b", 64), cutoff))
	rows, err := loadCancelledDiscoveryRows(context.Background(), db, cutoff)
	if err != nil || len(rows) != 2 || rows[0].LegacyStatus != "cancelled:older-cancel:realtime" || rows[0].UnprocessedRecords != 17 || rows[1].LegacyStatus != "cancelled:new-cancel:backfill" {
		t.Fatalf("cancelled history missing from fresh cutover: %+v %v", rows, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPassiveStreamCutoverRejectsMissingManifest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cursor := streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: "packet://bond0/passive-node", FileID: "boot-a", Offset: 0, DiscardedBeforeOffset: 0, ParserVersion: "passive-frame-v1"}
	mock.ExpectQuery("FROM stream_source_cutovers").WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "start_offset", "parser_version", "cancel_manifest_sha256"}).AddRow("node", "boot-a", int64(0), "passive-frame-v1", ""))
	if err := verifyPassiveStreamCutover(context.Background(), db, cursor, "node"); err == nil {
		t.Fatal("unaudited cutover accepted")
	}
}

func TestPreparePassiveStreamCutoverRejectsExpiredScopeBeforeAuditing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := discovery.Source{ID: "passive-node", Node: "node", Site: "site", Domain: "domain", Address: "bond0"}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "node", CollectorInstanceID: "boot", CampusID: "site", AccessDomain: "domain", InterfaceName: "bond0", ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now.Add(-time.Hour)}
	if _, err := preparePassiveStreamCutover(context.Background(), db, j, source, scope, t.TempDir(), "fresh-1", "cancel-1", "compatible-a", now.Add(-time.Hour)); err == nil {
		t.Fatal("expired capture scope activated fresh source")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
