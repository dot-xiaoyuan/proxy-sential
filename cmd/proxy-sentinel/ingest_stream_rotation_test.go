package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/streamlog"
)

func writeRotationFixture(t *testing.T, root string, archiveRaw []byte) (string, string) {
	t.Helper()
	current := filepath.Join(root, "logs", "current")
	date := filepath.Join(root, "logs", "2026-10-25")
	for _, dir := range []string{current, date} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(current, "device_dhcp_binding.log")
	archive := filepath.Join(date, "device_dhcp_binding.20:00:00-21:00:00.log.gz")
	if err := os.WriteFile(source, []byte("new-prefix\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(archiveRaw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return source, archive
}

func TestClosedBindingRotationAuditsBothFileGaps(t *testing.T) {
	for _, retired := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-close", true: "audited-retirement"}[retired], func(t *testing.T) {
			root := t.TempDir()
			oldPrefix, unread, oldTail := []byte("projected\n"), []byte("already-cancelled\n"), []byte("unprocessed-old\n")
			archiveRaw := append(append(append([]byte(nil), oldPrefix...), unread...), oldTail...)
			source, archive := writeRotationFixture(t, root, archiveRaw)
			journal, err := streamlog.Open(filepath.Join(root, "journal"))
			if err != nil {
				t.Fatal(err)
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cutoff := time.Now().UTC().Truncate(time.Second)
			priorHash := strings.Repeat("a", 64)
			closedOffset := len(oldPrefix) + len(unread)
			mock.ExpectQuery(`FROM stream_source_cutovers WHERE epoch=`).WithArgs("new-epoch", "zeek-dhcp-binding", source).WillReturnRows(sqlmock.NewRows([]string{"epoch", "source_kind", "source_path", "sensor_id", "file_id", "start_offset", "parser_version", "previous_release", "legacy_cutoff_at", "legacy_cancel_id", "cancel_manifest_sha256", "capture_scope_sha256", "state"}))
			mock.ExpectQuery(`SELECT count\(\*\) FROM stream_source_cutovers`).WithArgs("zeek-dhcp-binding", source, "new-epoch").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			mock.ExpectQuery(`SELECT count\(\*\) FROM ingest_batches`).WithArgs("sensor-a", "zeek-dhcp-binding", source, cutoff).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			retiredFile := ""
			if retired {
				retiredFile = source + ":1:42"
			}
			mock.ExpectQuery(`stream_retirement_cursor`).WithArgs("old-epoch", "zeek-dhcp-binding", source, priorHash).WillReturnRows(sqlmock.NewRows([]string{"sensor_id", "file_id", "legacy_reference", "content_sha256", "retired_file_id"}).AddRow("sensor-a", "old-file-id", closedOffset, priorHash, retiredFile))
			if retired {
				mock.ExpectQuery(`SELECT legacy_reference,content_sha256,unprocessed_bytes FROM stream_discard_manifest`).WithArgs("old-epoch", source).WillReturnRows(sqlmock.NewRows([]string{"legacy_reference", "content_sha256", "unprocessed_bytes"}).AddRow(retiredFile+":"+strconv.Itoa(len(oldPrefix))+":"+strconv.Itoa(closedOffset), hashRotationBytes(unread), len(unread)))
			} else {
				mock.ExpectQuery(`SELECT legacy_reference,content_sha256 FROM stream_discard_manifest`).WithArgs("old-epoch", source).WillReturnRows(sqlmock.NewRows([]string{"legacy_reference", "content_sha256"}).AddRow(source+":"+strconv.Itoa(len(oldPrefix))+":"+strconv.Itoa(closedOffset), hashRotationBytes(unread)))
			}
			mock.ExpectQuery(`SELECT batch_id,status,checksum`).WithArgs("sensor-a", "zeek-dhcp-binding", source, cutoff).WillReturnRows(sqlmock.NewRows([]string{"batch_id", "status", "checksum", "start_offset", "end_offset", "event_count", "started_at"}))
			mock.ExpectBegin()
			mock.ExpectExec(`INSERT INTO stream_source_cutovers`).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`INSERT INTO stream_discard_manifest`).WillReturnResult(sqlmock.NewResult(0, 4))
			mock.ExpectCommit()
			mock.ExpectExec(`UPDATE stream_source_cutovers SET state='active'`).WillReturnResult(sqlmock.NewResult(0, 1))
			scan, _, err := prepareControlledFileStreamAfterClosedWithRotation(context.Background(), db, journal, "zeek-dhcp-binding", "sensor-a", source, "new-epoch", "cancel-new", "compatible-a", strings.Repeat("b", 64), cutoff, "old-epoch", priorHash, archive)
			if err != nil {
				t.Fatal(err)
			}
			if scan.Records != 2 || scan.Bytes != int64(len(oldTail)+len("new-prefix\n")) || scan.Offset != int64(len("new-prefix\n")) {
				t.Fatalf("rotation gap counted incorrectly: %+v", scan)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}

			cursor, err := journal.LoadSource("zeek-dhcp-binding", source)
			if err != nil || cursor.Epoch != "new-epoch" || cursor.Offset != scan.Offset || cursor.KeyScheme != "generation-v2" || cursor.TailSHA256 == "" {
				t.Fatalf("fresh cursor: %+v %v", cursor, err)
			}

		})
	}
}

func TestClosedBindingRotationRejectsArchiveWithoutUnreadAnchor(t *testing.T) {
	source, archive := writeRotationFixture(t, t.TempDir(), []byte("different\nnew-tail\n"))
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT legacy_reference,content_sha256 FROM stream_discard_manifest`).WithArgs("old-epoch", source).WillReturnRows(sqlmock.NewRows([]string{"legacy_reference", "content_sha256"}).AddRow(source+":0:10", strings.Repeat("f", 64)))
	if _, err := verifyClosedRotationArchive(context.Background(), db, source, archive, "old-file-id", 10, "old-epoch"); err == nil {
		t.Fatal("unrelated archive was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRetiredBindingRotationChecksFinalFileChunks(t *testing.T) {
	for _, scenario := range []string{"valid", "changed", "missing", "gap", "wrong-file"} {
		t.Run(scenario, func(t *testing.T) {
			prefix, unread, tail := []byte("projected\n"), []byte("cancelled\n"), []byte("new-tail\n")
			source, archive := writeRotationFixture(t, t.TempDir(), append(append(append([]byte(nil), prefix...), unread...), tail...))
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			retiredID := source + ":1:42"
			end := len(prefix) + len(unread)
			ref := retiredID + ":" + strconv.Itoa(len(prefix)) + ":" + strconv.Itoa(end)
			hash := hashRotationBytes(unread)
			if scenario == "changed" {
				hash = strings.Repeat("f", 64)
			}
			if scenario == "gap" {
				ref = retiredID + ":" + strconv.Itoa(len(prefix)) + ":" + strconv.Itoa(end-1)
			}
			if scenario == "wrong-file" {
				ref = source + ":1:43:0:" + strconv.Itoa(end)
			}
			rows := sqlmock.NewRows([]string{"legacy_reference", "content_sha256", "unprocessed_bytes"})
			if scenario != "missing" {
				rows.AddRow(ref, hash, len(unread))
			}
			mock.ExpectQuery(`SELECT legacy_reference,content_sha256,unprocessed_bytes FROM stream_discard_manifest`).WithArgs("prior", source).WillReturnRows(rows)
			entries, err := verifyRetiredBindingRotationArchive(context.Background(), db, source, archive, retiredID, int64(end), "prior")
			if scenario == "valid" {
				if err != nil || len(entries) != 2 || entries[0].UnprocessedRecords != 1 || entries[0].UnprocessedBytes != int64(len(tail)) {
					t.Fatalf("tail: %+v %v", entries, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid retirement anchor")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
