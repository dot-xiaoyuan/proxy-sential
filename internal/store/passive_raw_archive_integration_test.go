package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPassiveArchiveReceiptAndRestore(t *testing.T) {
	pgdsn, chdsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if pgdsn == "" || chdsn == "" {
		t.Skip("isolated PostgreSQL and ClickHouse required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", pgdsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("archive_test_%d", time.Now().UnixNano())
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := db.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema)
	defer db.Exec("DROP SCHEMA " + schema + " CASCADE")
	exec("CREATE TABLE discovery_observations(id text PRIMARY KEY,data jsonb,observed_at timestamptz,withdrawn boolean); CREATE TABLE ingest_batches(batch_id text PRIMARY KEY,source_path text,file_id text,start_offset bigint,end_offset bigint,checksum text,committed_at timestamptz,status text)")
	pg, e := os.ReadFile("../../migrations/postgres/255_passive_evidence_receipts.sql")
	if e != nil {
		t.Fatal(e)
	}
	exec(string(pg))
	exec("ALTER TABLE discovery_observations ENABLE TRIGGER passive_archive_capture")
	ch, e := NewClickHouseStore(ClickHouseOptions{DSN: chdsn})
	if e != nil {
		t.Fatal(e)
	}
	ddl, e := os.ReadFile("../../migrations/clickhouse/075_passive_discovery_raw_archive.sql")
	if e != nil {
		t.Fatal(e)
	}
	if err = ch.exec(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	store := DBStore{pg: &PostgresStore{db: db}, ch: ch}
	dir := t.TempDir()
	path := filepath.Join(dir, "discovery.log")
	line := []byte("retained product evidence")
	data := append(append([]byte(nil), line...), []byte("\r\ncompanion\n")...)
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	inode := info.Sys().(*syscall.Stat_t)
	accepted := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	batch := schema
	exec("INSERT INTO ingest_batches VALUES($1,$2,$3,0,$4,$5,$6,'committed')", batch, path, fmt.Sprintf("%s:%d:%d", path, inode.Dev, inode.Ino), len(data), passiveRawDigest(data), accepted)
	ref := func(hash string) map[string]any {
		return map[string]any{"content_sha256": hash, "ingest_source_ref": map[string]string{"batch_id": batch, "content_sha256": passiveRawDigest(data)}}
	}
	payload, e := json.Marshal(map[string]any{"event_id": "proof", "evidence": map[string]any{"raw_ref": map[string]any{"records": []map[string]any{{"raw_ref": ref(passiveRawDigest(line))}, {"raw_ref": ref(passiveRawDigest([]byte("missing")))}}}}})
	if e != nil {
		t.Fatal(e)
	}
	exec("INSERT INTO discovery_observations VALUES('one',$1,now(),false),('two',$1,now(),false)", payload)
	process := func() {
		t.Helper()
		if did, e := store.archivePassiveBatch(ctx, []string{dir}); e != nil || !did {
			t.Fatal(did, e)
		}
	}
	// The wanted row is present with the same inode, but the companion changed:
	// neither the PG receipt nor the CH row may be written on this hash alone.
	wrong := bytes.Replace(data, []byte("companion"), []byte("different"), 1)
	if e = os.WriteFile(path, wrong, 0600); e != nil {
		t.Fatal(e)
	}
	process()
	var verified, waiting, members int
	if e = db.QueryRow("SELECT count(*) FILTER(WHERE verified_at IS NOT NULL),count(*) FILTER(WHERE verified_at IS NULL AND attempts=1) FROM passive_archive_rows").Scan(&verified, &waiting); e != nil || verified != 0 || waiting != 2 {
		t.Fatal(verified, waiting, e)
	}
	provisional, e := ch.query(ctx, "SELECT count() FROM passive_discovery_raw_archive WHERE batch_id="+chQuote(batch)+" FORMAT TabSeparated")
	if e != nil || strings.TrimSpace(string(provisional)) != "0" {
		t.Fatal(string(provisional), e)
	}
	if e = os.WriteFile(path+".1", data, 0600); e != nil {
		t.Fatal(e)
	}
	exec("UPDATE passive_archive_rows SET next_attempt=now() WHERE verified_at IS NULL")
	process()
	if e = db.QueryRow("SELECT count(*) FILTER(WHERE verified_at IS NOT NULL AND accepted_at=$1),count(*) FILTER(WHERE verified_at IS NULL AND attempts=2),(SELECT count(*) FROM passive_archive_members) FROM passive_archive_rows", accepted).Scan(&verified, &waiting, &members); e != nil || verified != 1 || waiting != 1 || members != 4 {
		t.Fatal(verified, waiting, members, e)
	}
	// Simulate losing the PG commit after a successful CH insert and source rotation.
	exec("UPDATE passive_archive_rows SET verified_at=NULL WHERE verified_at IS NOT NULL")
	if e = os.Remove(path + ".1"); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	process()
	raw, e := ch.query(ctx, "SELECT raw_b64 FROM passive_discovery_raw_archive WHERE batch_id="+chQuote(batch)+" FORMAT JSONEachRow")
	if e != nil {
		t.Fatal(e)
	}
	var restored []struct {
		Data string `json:"raw_b64"`
	}
	if e = decodeJSONEachRow(raw, &restored); e != nil || len(restored) != 1 {
		t.Fatal(len(restored), e)
	}
	original, e := base64.StdEncoding.DecodeString(restored[0].Data)
	if e != nil || !bytes.Equal(original, line) {
		t.Fatal("restore differs", e)
	}
}
