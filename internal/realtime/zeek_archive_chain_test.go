package realtime

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestZeekBindingDrainsContiguousArchivesAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current", "device_dhcp_message.log")
	archiveDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
	for _, directory := range []string{filepath.Dir(path), archiveDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	line := func(uid string) []byte {
		return []byte(`{"ts":1792890000,"uid":"` + uid + `","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n")
	}
	first, second, third, fourth, current := line("C1"), line("C2"), line("C3"), line("C4"), line("C5")
	old := append(append([]byte(nil), first...), second...)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	journalDir := filepath.Join(dir, "journal")
	j, err := streamlog.Open(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	j.SetRawResolver(resolveZeekSourceRaw)
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	tail := sha256.Sum256(first)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-chain", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(tail[:]), ParserVersion: "zeek-dhcp-message-v1", KeyScheme: "generation-v2", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	writeZeekChainArchive(t, filepath.Join(archiveDir, "device_dhcp_message.09:00:00-10:00:00.log.gz"), old)
	writeZeekChainArchive(t, filepath.Join(archiveDir, "device_dhcp_message.10:00:00-11:00:00.log.gz"), append(append([]byte(nil), third...), fourth...))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatal(err)
	}
	wantRaw := [][]byte{second, third, fourth, current}
	wantGeneration := []uint64{1, 2, 2, 3}
	opts := Options{SensorID: "sensor-a", MaxBatchBytes: int64(len(first))}
	var previousID string
	for i, want := range wantRaw {
		// A restart at either archive boundary must keep the same source cursor.
		if i == 1 || i == 3 {
			j, err = streamlog.Open(journalDir)
			if err != nil {
				t.Fatal(err)
			}
			j.SetRawResolver(resolveZeekSourceRaw)
			if _, err := j.RecoverSource(source.Kind, path); err != nil {
				t.Fatalf("recover source before step %d: %v", i, err)
			}
		}
		id, captured, err := CaptureStreamOnce(context.Background(), j, opts, source)
		if err != nil || !captured {
			t.Fatalf("capture archive chain step %d: %s %t %v", i, id, captured, err)
		}
		state, err := j.Load(id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(state.Segment.Raw, want) || state.Segment.SourceGeneration != wantGeneration[i] || state.Segment.PreviousFileID != previousID && i > 0 {
			t.Fatalf("archive chain step %d lost order or raw bytes: %+v", i, state.Segment)
		}
		sum := sha256.Sum256(want)
		if state.Segment.RawSHA256 != hex.EncodeToString(sum[:]) || !state.Committed {
			t.Fatalf("archive chain step %d lost durable hash or cursor commit: %+v", i, state)
		}
		cursor, err := j.LoadSource(source.Kind, path)
		if err != nil || cursor.LastSegmentID != id || cursor.Generation != wantGeneration[i] {
			t.Fatalf("archive chain step %d cursor: %+v %v", i, cursor, err)
		}
		previousID = state.Segment.FileID
	}
}

func TestZeekBindingRejectsMissingArchiveInChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current", "device_dhcp_message.log")
	archiveDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
	for _, directory := range []string{filepath.Dir(path), archiveDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := []byte("old\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	tail := sha256.Sum256(old)
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-chain", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), Offset: int64(len(old)), TailBytes: len(old), TailSHA256: hex.EncodeToString(tail[:]), ParserVersion: "zeek-dhcp-message-v1", KeyScheme: "generation-v2", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	writeZeekChainArchive(t, filepath.Join(archiveDir, "device_dhcp_message.09:00:00-10:00:00.log.gz"), old)
	writeZeekChainArchive(t, filepath.Join(archiveDir, "device_dhcp_message.11:00:00-12:00:00.log.gz"), []byte("later\n"))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source); captured || !errors.Is(err, ErrStreamSourceGap) {
		t.Fatalf("missing hourly archive advanced cursor: captured=%t err=%v", captured, err)
	}
}

func TestZeekBindingWaitsForCompleteSuccessorArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current", "device_dhcp_message.log")
	archiveDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
	for _, directory := range []string{filepath.Dir(path), archiveDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := []byte("old\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	tail := sha256.Sum256(old)
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-chain", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), Offset: int64(len(old)), TailBytes: len(old), TailSHA256: hex.EncodeToString(tail[:]), ParserVersion: "zeek-dhcp-message-v1", KeyScheme: "generation-v2", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	writeZeekChainArchive(t, filepath.Join(archiveDir, "device_dhcp_message.09:00:00-10:00:00.log.gz"), old)
	next := filepath.Join(archiveDir, "device_dhcp_message.10:00:00-11:00:00.log.gz")
	writeZeekChainArchive(t, next, []byte("successor\n"))
	stat, err := os.Stat(next)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(next, stat.Size()-8); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("current\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source); captured || !errors.Is(err, ErrStreamArchivePending) {
		t.Fatalf("incomplete successor archive advanced cursor: captured=%t err=%v", captured, err)
	}
	cursor, err := j.LoadSource(source.Kind, path)
	if err != nil || cursor.FileID != fileIdentity(path, info) || cursor.Offset != int64(len(old)) || cursor.LastSegmentID != "" {
		t.Fatalf("incomplete successor changed cursor: %+v %v", cursor, err)
	}
}

func TestZeekRawResolverRechecksCachedArchiveAfterItMoves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current", "device_dhcp_message.log")
	archiveDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
	for _, directory := range []string{filepath.Dir(path), archiveDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := []byte("original archived bytes\n")
	sum := sha256.Sum256(raw)
	segment := streamlog.Segment{Source: "zeek-dhcp-binding", SourceBackedRaw: true, SourcePath: path,
		FileID: "old-file-id", StartOffset: 0, EndOffset: int64(len(raw)), RawSHA256: hex.EncodeToString(sum[:])}
	first := filepath.Join(archiveDir, "device_dhcp_message.12:00:00-13:00:00.log.gz")
	writeZeekChainArchive(t, first, raw)
	got, err := ResolveZeekSourceRaw(segment)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("initial archive resolution: %v", err)
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(archiveDir, "device_dhcp_message.13:00:00-14:00:00.log.gz")
	writeZeekChainArchive(t, second, raw)
	got, err = ResolveZeekSourceRaw(segment)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("stale cached archive was not rechecked: %v", err)
	}
}

func writeZeekChainArchive(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
