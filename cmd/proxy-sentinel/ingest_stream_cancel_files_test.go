package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/streamlog"
)

func cancellationCursor(t *testing.T, path string, prefix []byte) streamlog.SourceCursor {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(prefix)
	return streamlog.SourceCursor{Epoch: "old", Source: "device-signals", Path: path, FileID: realtime.FileIdentity(path, info), Offset: int64(len(prefix)), TailBytes: len(prefix), TailSHA256: hex.EncodeToString(sum[:])}
}
func writeCancelGzip(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	z := gzip.NewWriter(f)
	if _, e = z.Write(raw); e != nil {
		t.Fatal(e)
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestCancellationFilesAcrossCompressedRotations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	prefix := []byte("already-accepted\n")
	if e := os.WriteFile(path, append(append([]byte{}, prefix...), []byte("old-tail\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	cursor := cancellationCursor(t, path, prefix)
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	writeCancelGzip(t, path+".2.gz", append(append([]byte{}, prefix...), []byte("old-tail\n")...))
	if e := os.WriteFile(path+".1", []byte("intermediate\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("before-boundary\npartial"), 0600); e != nil {
		t.Fatal(e)
	}
	audit, e := snapshotCancelledSourceFiles(cursor, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	if audit.Offset != int64(len("before-boundary\n")) || len(audit.Entries) != 3 {
		t.Fatalf("bad boundary %+v", audit)
	}
	var records, bytes int64
	for _, entry := range audit.Entries {
		records += entry.UnprocessedRecords
		bytes += entry.UnprocessedBytes
		if entry.LegacyStatus != "cancelled_unprocessed" {
			t.Fatal(entry)
		}
	}
	if records != 3 || bytes != int64(len("old-tail\nintermediate\nbefore-boundary\n")) {
		t.Fatalf("records=%d bytes=%d", records, bytes)
	}
	if e = retainCancellationFiles(audit, filepath.Join(dir, "protected")); e != nil {
		t.Fatal(e)
	}
	if e = validateRetainedCancellationFiles(cursor, audit); e != nil {
		t.Fatal("compressed rotation retention failed", e)
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.WriteString("-completed\nfresh\n")
	_ = f.Close()
	if e = validateCancellationBoundary(cursor, audit); e != nil {
		t.Fatalf("append invalidated fixed boundary: %v", e)
	}
	if e = validateRetainedCancellationFiles(cursor, audit); e != nil {
		t.Fatalf("append invalidated retained ranges: %v", e)
	}
	if e = os.WriteFile(path+".1", []byte("rewritten!!!\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = validateRetainedCancellationFiles(cursor, audit); e == nil {
		t.Fatal("rewritten intermediate source accepted")
	}
	if e = os.WriteFile(path, []byte("changed-prefix!!\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = validateCancellationBoundary(cursor, audit); e == nil {
		t.Fatal("rewrite accepted")
	}
}
func TestCancellationFileAuditRejectsMissingDuplicateOrUnboundedAnchor(t *testing.T) {
	for _, kind := range []string{"missing", "duplicate", "bound"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ttl.jsonl")
			prefix := []byte("anchor\n")
			if e := os.WriteFile(path, prefix, 0600); e != nil {
				t.Fatal(e)
			}
			cursor := cancellationCursor(t, path, prefix)
			_ = os.Remove(path)
			writeCancelGzip(t, path+".2.gz", []byte("different\n"))
			_ = os.WriteFile(path+".1", []byte("tail\n"), 0600)
			_ = os.WriteFile(path, []byte("fresh\n"), 0600)
			limit := int64(1 << 20)
			if kind == "duplicate" {
				writeCancelGzip(t, path+".2.gz", prefix)
				writeCancelGzip(t, path+".1.gz", prefix)
			}
			if kind == "bound" {
				writeCancelGzip(t, path+".2.gz", prefix)
				limit = 2
			}
			if _, e := snapshotCancelledSourceFiles(cursor, limit); e == nil {
				t.Fatal("unsafe audit accepted")
			}
		})
	}
}
func TestCancellationFileInventoryOrdersDateAndNumericRotations(t *testing.T) {
	for _, names := range [][]string{{".1", ".2.gz", ".3.gz"}, {"-20261028-034301", "-20261027-034301.gz"}} {
		dir := t.TempDir()
		path := filepath.Join(dir, "handshake.jsonl")
		_ = os.WriteFile(path, []byte("x\n"), 0600)
		for _, n := range names {
			_ = os.WriteFile(path+n, []byte("x\n"), 0600)
		}
		paths, e := cancellationSourcePaths(streamlog.SourceCursor{Source: "device-signals", Path: path})
		if e != nil {
			t.Fatal(e)
		}
		if len(paths) != len(names)+1 || paths[len(paths)-1] != path || paths[0] != path+names[len(names)-1] {
			t.Fatal(paths)
		}
	}
}

func TestCancellationSavedBoundaryIsImmutableAcrossPreviewAndRetry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	prefix := []byte("accepted\n")
	if e := os.WriteFile(path, append(append([]byte{}, prefix...), []byte("cancelled\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	cursor := cancellationCursor(t, path, prefix)
	snapshot := filepath.Join(dir, "audit.json")
	first, e := loadOrSnapshotCancelledFiles(snapshot, cursor)
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.WriteString("fresh-after-snapshot\n")
	_ = f.Close()
	second, e := loadOrSnapshotCancelledFiles(snapshot, cursor)
	if e != nil {
		t.Fatal(e)
	}
	if second.Offset != first.Offset || second.Offset != int64(len("accepted\ncancelled\n")) {
		t.Fatal("retry moved the fixed boundary")
	}
	cursor.Offset++
	if _, e = loadOrSnapshotCancelledFiles(snapshot, cursor); e == nil {
		t.Fatal("foreign cursor reused snapshot")
	}
}

func TestCancellationRetainsOriginalInodesAcrossRotationAndRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	prefix := []byte("accepted\n")
	if err := os.WriteFile(path, append(append([]byte{}, prefix...), []byte("cancelled\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	cursor := cancellationCursor(t, path, prefix)
	snapshot := filepath.Join(dir, "audit.json")
	audit, err := loadOrSnapshotCancelledFiles(snapshot, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.RetainedFiles) != 1 {
		t.Fatal("original source was not protected", audit.RetainedFiles)
	}
	original, _ := os.Stat(path)
	protected, err := os.Stat(audit.RetainedFiles[0])
	if err != nil || !os.SameFile(original, protected) {
		t.Fatalf("retention copied or lost the original inode: %v", err)
	}
	if _, err = loadOrSnapshotCancelledFiles(snapshot, cursor); err != nil {
		t.Fatal("retention retry failed", err)
	}
	if err = os.Remove(audit.RetainedFiles[0]); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(audit.RetainedFiles[0], []byte("different evidence\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadOrSnapshotCancelledFiles(snapshot, cursor); err == nil {
		t.Fatal("replaced retained evidence was accepted")
	}
	if err = os.Remove(audit.RetainedFiles[0]); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(path, audit.RetainedFiles[0]); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(audit.RetainedFiles[0])
	if err != nil || string(retained) != "accepted\ncancelled\n" {
		t.Fatalf("source rotation retired the sole original: %q %v", retained, err)
	}
}

func TestCancellationRetentionRejectsChangedAuditedRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	prefix := []byte("accepted\n")
	if err := os.WriteFile(path, append(append([]byte{}, prefix...), []byte("cancelled\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	cursor := cancellationCursor(t, path, prefix)
	snapshot := filepath.Join(dir, "audit.json")
	if _, err := loadOrSnapshotCancelledFiles(snapshot, cursor); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteAt([]byte("altered!!"), int64(len(prefix)))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = loadOrSnapshotCancelledFiles(snapshot, cursor); err == nil {
		t.Fatal("changed audited range was accepted")
	}
}
