package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/streamlog"
)

func TestZeekFreshCutoverAuditsOnlyCompleteOldRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.log")
	old := []byte("#path dhcp\nold-a\nold-b\npartial")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := scanZeekCutoverBytes(f, int64(len("#path dhcp\n")), int64(len(old)))
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := []byte("old-a\nold-b\n")
	wantHash := sha256.Sum256(wantBytes)
	if got.Offset != int64(len("#path dhcp\n"))+int64(len(wantBytes)) || got.Records != 2 || got.Bytes != int64(len(wantBytes)) || got.SHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("fresh cutoff lost or counted a partial event: %+v", got)
	}
}

func TestDeviceSignalCancellationIsAuditedInVerifiableChunks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	raw := []byte("one\ntwo\nthree\npartial")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	total, chunks, err := scanFileCutoverChunks(file, 0, int64(len(raw)), false, 7)
	if err != nil {
		t.Fatal(err)
	}
	if total.Offset != int64(len("one\ntwo\nthree\n")) || total.Records != 3 || len(chunks) != 2 {
		t.Fatalf("total=%+v chunks=%+v", total, chunks)
	}
	start := int64(0)
	for _, chunk := range chunks {
		body := raw[start:chunk.Offset]
		sum := sha256.Sum256(body)
		if chunk.SHA256 != hex.EncodeToString(sum[:]) || chunk.Bytes != int64(len(body)) {
			t.Fatalf("invalid chunk %+v", chunk)
		}
		start = chunk.Offset
	}
	if start != total.Offset {
		t.Fatalf("chunk ranges stop at %d, want %d", start, total.Offset)
	}
}

func TestZeekFreshCutoverRecordsGapBeforeActivatingCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.log")
	if err := os.WriteFile(path, []byte("#path dhcp\nold\npartial"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Truncate(time.Second)
	mock.ExpectQuery(`FROM stream_source_cutovers WHERE epoch=`).WithArgs("fresh", "zeek-dhcp", path).WillReturnRows(sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "sensor_id", "file_id", "start_offset", "parser_version", "previous_release", "legacy_cutoff_at", "legacy_cancel_id", "cancel_manifest_sha256", "capture_scope_sha256", "state"}))
	mock.ExpectQuery(`SELECT count\(\*\) FROM stream_source_cutovers`).WithArgs("zeek-dhcp", path, "fresh").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT count\(\*\) FROM ingest_batches`).WithArgs("sensor-a", "zeek-dhcp", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`FROM ingest_checkpoints`).WithArgs("sensor-a", "zeek-dhcp", path).WillReturnRows(sqlmock.NewRows([]string{"file_id", "committed_offset"}))
	mock.ExpectQuery(`SELECT batch_id,status,checksum`).WithArgs("sensor-a", "zeek-dhcp", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "status", "checksum", "start_offset", "end_offset", "event_count", "started_at"}))
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO stream_source_cutovers`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_discard_manifest`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec(`UPDATE stream_source_cutovers SET state='active'`).WillReturnResult(sqlmock.NewResult(0, 1))
	scan, manifest, err := prepareZeekDHCPStream(context.Background(), db, j, "sensor-a", path, "fresh", "cancel-1", "compatible-a", strings.Repeat("a", 64), cutoff)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource("zeek-dhcp", path)
	if err != nil {
		t.Fatal(err)
	}
	if cursor.DiscardedBeforeOffset != scan.Offset || scan.Records != 1 || len(manifest) != 64 {
		t.Fatalf("uncertified fresh start: %+v %+v %q", scan, cursor, manifest)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestControlledSignalFreshCutoverKeepsPartialLineUnread(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	complete := []byte(`{"schema_version":"v1","event_id":"old","type":"device"}` + "\n")
	if err := os.WriteFile(path, append(append([]byte{}, complete...), []byte(`{"partial":`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Truncate(time.Second)
	mock.ExpectQuery(`FROM stream_source_cutovers WHERE epoch=`).WithArgs("fresh-ttl", "device-signals", path).WillReturnRows(sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "sensor_id", "file_id", "start_offset", "parser_version", "previous_release", "legacy_cutoff_at", "legacy_cancel_id", "cancel_manifest_sha256", "capture_scope_sha256", "state"}))
	mock.ExpectQuery(`SELECT count\(\*\) FROM stream_source_cutovers`).WithArgs("device-signals", path, "fresh-ttl").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT count\(\*\) FROM ingest_batches`).WithArgs("sensor-a", "device-signals", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`FROM ingest_checkpoints`).WithArgs("sensor-a", "device-signals", path).WillReturnRows(sqlmock.NewRows([]string{"file_id", "committed_offset"}))
	mock.ExpectQuery(`SELECT batch_id,status,checksum`).WithArgs("sensor-a", "device-signals", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "status", "checksum", "start_offset", "end_offset", "event_count", "started_at"}))
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO stream_source_cutovers`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_discard_manifest`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec(`UPDATE stream_source_cutovers SET state='active'`).WillReturnResult(sqlmock.NewResult(0, 1))
	scan, _, err := prepareControlledFileStream(context.Background(), db, j, "device-signals", "sensor-a", path, "fresh-ttl", "cancel-ttl", "compatible-a", strings.Repeat("b", 64), cutoff)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := j.LoadSource("device-signals", path)
	if err != nil || cursor.DiscardedBeforeOffset != int64(len(complete)) || cursor.ParserVersion != "device-v1" || scan.Records != 1 {
		t.Fatalf("controlled signal cutoff lost position or partial line: scan=%+v cursor=%+v err=%v", scan, cursor, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestControlledSignalDiscardManifestNamesItsActualSource(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Truncate(time.Second)
	mock.ExpectQuery(`SELECT batch_id,status,checksum`).WithArgs("sensor-a", "device-signals", "/signals/ttl.jsonl", cutoff).
		WillReturnRows(sqlmock.NewRows([]string{"batch_id", "status", "checksum", "start_offset", "end_offset", "event_count", "started_at"}))
	entries, err := legacyFileDiscardEntries(context.Background(), db, "device-signals", "sensor-a", "/signals/ttl.jsonl", "file-1", 100, zeekCutoverBytes{Offset: 120, Records: 2, Bytes: 20, SHA256: strings.Repeat("a", 64)}, cutoff)
	if err != nil || len(entries) != 1 || entries[0].LegacyKind != "unread_device_signal_file" {
		t.Fatalf("controlled source audit mislabeled: entries=%+v err=%v", entries, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBindingRestartAuditsOnlyBytesAfterClosedStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_dhcp_binding.log")
	old := []byte("already-projected\n")
	newInput := []byte("unprocessed-after-close\n")
	if err := os.WriteFile(path, append(append([]byte(nil), old...), newInput...), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cutoff := time.Now().UTC().Truncate(time.Second)
	priorHash := strings.Repeat("c", 64)
	mock.ExpectQuery(`FROM stream_source_cutovers WHERE epoch=`).WithArgs("fresh-2", "zeek-dhcp-binding", path).WillReturnRows(sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "sensor_id", "file_id", "start_offset", "parser_version", "previous_release", "legacy_cutoff_at", "legacy_cancel_id", "cancel_manifest_sha256", "capture_scope_sha256", "state"}))
	mock.ExpectQuery(`SELECT count\(\*\) FROM stream_source_cutovers`).WithArgs("zeek-dhcp-binding", path, "fresh-2").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT count\(\*\) FROM ingest_batches`).WithArgs("sensor-a", "zeek-dhcp-binding", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`stream_retirement_cursor`).WithArgs("fresh-1", "zeek-dhcp-binding", path, priorHash).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "legacy_reference", "content_sha256", "retired_file_id"}).AddRow("sensor-a", realtime.FileIdentity(path, info), "18", priorHash, ""))
	mock.ExpectQuery(`SELECT batch_id,status,checksum`).WithArgs("sensor-a", "zeek-dhcp-binding", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "status", "checksum", "start_offset", "end_offset", "event_count", "started_at"}))
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO stream_source_cutovers`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO stream_discard_manifest`).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	mock.ExpectExec(`UPDATE stream_source_cutovers SET state='active'`).WillReturnResult(sqlmock.NewResult(0, 1))
	scan, _, err := prepareControlledFileStreamAfterClosed(context.Background(), db, j, "zeek-dhcp-binding", "sensor-a", path, "fresh-2", "cancel-2", "compatible-a", strings.Repeat("a", 64), cutoff, "fresh-1", priorHash)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Records != 1 || scan.Bytes != int64(len(newInput)) || scan.Offset != int64(len(old)+len(newInput)) {
		t.Fatalf("closed stream history counted as new gap: %+v", scan)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBindingRestartAcrossRotationRequiresAuditedNewFileID(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(map[bool]string{true: "audited", false: "missing-proof"}[allowed], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "device_dhcp_binding.log")
			old := []byte("already-audited-new-file-prefix\n")
			newInput := []byte("new-unprocessed-line\n")
			if err := os.WriteFile(path, append(append([]byte(nil), old...), newInput...), 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cutoff := time.Now().UTC().Truncate(time.Second)
			priorHash := strings.Repeat("d", 64)
			retiredFile := realtime.FileIdentity(path, info)
			if !allowed {
				retiredFile = ""
			}
			mock.ExpectQuery(`FROM stream_source_cutovers WHERE epoch=`).WithArgs("fresh-rotated", "zeek-dhcp-binding", path).WillReturnRows(sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "sensor_id", "file_id", "start_offset", "parser_version", "previous_release", "legacy_cutoff_at", "legacy_cancel_id", "cancel_manifest_sha256", "capture_scope_sha256", "state"}))
			mock.ExpectQuery(`SELECT count\(\*\) FROM stream_source_cutovers`).WithArgs("zeek-dhcp-binding", path, "fresh-rotated").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			mock.ExpectQuery(`SELECT count\(\*\) FROM ingest_batches`).WithArgs("sensor-a", "zeek-dhcp-binding", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			mock.ExpectQuery(`stream_retirement_cursor`).WithArgs("prior-epoch", "zeek-dhcp-binding", path, priorHash).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "legacy_reference", "content_sha256", "retired_file_id"}).AddRow("sensor-a", "old-Zeek-file-id", len(old), priorHash, retiredFile))
			if allowed {
				mock.ExpectQuery(`SELECT batch_id,status,checksum`).WithArgs("sensor-a", "zeek-dhcp-binding", path, cutoff).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "status", "checksum", "start_offset", "end_offset", "event_count", "started_at"}))
				mock.ExpectBegin()
				mock.ExpectExec(`INSERT INTO stream_source_cutovers`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`INSERT INTO stream_discard_manifest`).WillReturnResult(sqlmock.NewResult(0, 2))
				mock.ExpectCommit()
				mock.ExpectExec(`UPDATE stream_source_cutovers SET state='active'`).WillReturnResult(sqlmock.NewResult(0, 1))
			}
			scan, _, err := prepareControlledFileStreamAfterClosed(context.Background(), db, j, "zeek-dhcp-binding", "sensor-a", path, "fresh-rotated", "cancel-rotated", "compatible-a", strings.Repeat("a", 64), cutoff, "prior-epoch", priorHash)
			if allowed {
				if err != nil || scan.Records != 1 || scan.Bytes != int64(len(newInput)) {
					t.Fatalf("rotated audit counted prior bytes: %+v %v", scan, err)
				}
			} else if !errors.Is(err, streamlog.ErrContentConflict) {
				t.Fatalf("rotation without matching file proof accepted: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
