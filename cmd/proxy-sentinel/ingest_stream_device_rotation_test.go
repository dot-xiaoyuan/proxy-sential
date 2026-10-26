package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/realtime"
)

func TestClosedDeviceRotationRequiresEveryAuditedChunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ttl.jsonl")
	old := []byte("committed\nfirst\nsecond\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fresh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	fileID := realtime.FileIdentity(path, info)
	start := int64(len("committed\n"))
	_, chunks, err := scanFileCutoverChunks(file, start, info.Size(), false, 8<<20)
	file.Close()
	if err != nil || len(chunks) != 1 {
		t.Fatalf("chunks=%+v err=%v", chunks, err)
	}
	ref := fileID + ":" + strconv.FormatInt(start, 10) + ":" + strconv.FormatInt(chunks[0].Offset, 10)
	for _, valid := range []bool{true, false} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		hash := chunks[0].SHA256
		if !valid {
			hash = "bad"
		}
		mock.ExpectQuery(`SELECT legacy_reference,content_sha256`).WithArgs("old-epoch", path).WillReturnRows(sqlmock.NewRows([]string{"ref", "hash", "records", "bytes"}).AddRow(ref, hash, chunks[0].Records, chunks[0].Bytes))
		entries, err := verifyClosedDeviceRotation(context.Background(), db, path, path+".1", fileID, start, "old-epoch")
		if valid && (err != nil || len(entries) != 2 || entries[0].UnprocessedRecords != 2) {
			t.Fatalf("valid rotation: entries=%+v err=%v", entries, err)
		}
		if !valid && err == nil {
			t.Fatal("changed audit hash was accepted")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}
