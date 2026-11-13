package realtime

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestDeviceSignalCompressedRotationResumesOldCursorAcrossProtectedFiles(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	recovery := filepath.Join(dir, "protected")
	t.Setenv("PROXY_SENTINEL_DEVICE_SIGNAL_RECOVERY_DIR", recovery)
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "signal-owner", CampusID: "campus-a", AccessDomain: "bond0", InterfaceName: "bond0", ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
	line := func(id string) []byte {
		event := normalized.Event{SchemaVersion: "v1", EventID: id, Source: "device-signals", SourceEventType: "ssdp", Type: "device", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor-a", "collector_instance_id": "signal-owner", "interface": "bond0"}, Subject: map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"origin": "ssdp"}}
		raw, err := json.Marshal(scope.Apply(event))
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	first, unread, next, current := line("first"), line("unread"), line("next"), line("current")
	if err := os.WriteFile(path, append(append([]byte{}, first...), unread...), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	oldID := fileIdentity(path, old)
	j, err := streamlog.Open(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(first)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "existing-epoch", Source: "device-signals", Path: path, FileID: oldID, Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(sum[:]), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	writeGzipFixture(t, filepath.Join(recovery, "ttl.jsonl.2.gz"), append(append([]byte{}, first...), unread...))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recovery, "ttl.jsonl.1"), next, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(recovery, "ttl.jsonl.1"), path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(recovery, "ttl-live-20261113T1100.jsonl")); err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "device-signals", Path: path, CaptureScope: scope, ControlledInterface: "bond0"}
	read := func(want string) {
		t.Helper()
		id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a", MaxBatchBytes: 1 << 20}, source)
		if err != nil || !captured {
			t.Fatalf("capture %s: id=%s captured=%t err=%v", want, id, captured, err)
		}
		state, err := j.Load(id)
		if err != nil || len(state.Segment.Events) != 1 || state.Segment.Events[0].RawRef["producer_event_id"] != want {
			t.Fatalf("capture %s produced %+v: %v", want, state.Segment.Events, err)
		}
		cursor, err := j.LoadSource(source.Kind, path)
		if err != nil || cursor.Epoch != "existing-epoch" {
			t.Fatalf("source epoch changed: %+v %v", cursor, err)
		}
	}
	read("unread")
	j, err = streamlog.Open(j.Directory()) // Recover without changing the epoch or offset.
	if err != nil {
		t.Fatal(err)
	}
	clearSignalGzip(path) // Simulate the process losing its in-memory inflater.
	read("next")
	read("current")
	if err := os.Remove(path + ".1"); err != nil {
		t.Fatal(err)
	}
	writeGzipFixture(t, path+".1.gz", current)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, line("future"), 0o600); err != nil {
		t.Fatal(err)
	}
	read("future")
}

func TestLegacyHandshakeCursorChangesToBirthIDOnlyAfterVerifiedRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "handshake.jsonl")
	first, unread, next := []byte("first\n"), []byte("unread\n"), []byte("next\n")
	if err := os.WriteFile(path, append(append([]byte{}, first...), unread...), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := fileIdentity(path, info)
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	firstHash := sha256.Sum256(first)
	cursor := streamlog.SourceCursor{FileID: legacy, Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(firstHash[:])}
	read, err := readDeviceSignalChunk(path, cursor, 1<<20)
	if err != nil || string(read.data) != string(unread) || read.fileID != legacy || read.verifiedRotation {
		t.Fatalf("legacy live bytes must keep their original identity: %+v %v", read, err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, next, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err = readDeviceSignalChunk(path, cursor, 1<<20)
	if err != nil || string(read.data) != string(unread) || read.fileID != legacy || read.verifiedRotation {
		t.Fatalf("legacy unread bytes must keep their original identity: %+v %v", read, err)
	}
	unreadHash := sha256.Sum256(unread)
	cursor.Offset = read.end
	cursor.TailBytes = len(unread)
	cursor.TailSHA256 = hex.EncodeToString(unreadHash[:])
	read, err = readDeviceSignalChunk(path, cursor, 1<<20)
	if err != nil || string(read.data) != string(next) || !read.verifiedRotation || read.fileID != FileIdentityBirth(path, mustStat(t, path)) {
		t.Fatalf("verified successor must acquire its birth identity: %+v %v", read, err)
	}
}

func TestProtectedFlowAnchorsKeepSourceOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flow-syn.jsonl")
	recovery := filepath.Join(dir, "protected")
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(deviceSignalRecoveryDirEnv, recovery)
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	old := []byte("accepted\nunread\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	info := mustStat(t, path)
	oldID := FileIdentityBirth(path, info)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path+".1", filepath.Join(recovery, "flow-syn.jsonl.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("successor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(recovery, "flow-syn-live-20261113T1800.jsonl")); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("accepted\n"))
	cursor := streamlog.SourceCursor{FileID: oldID, Offset: int64(len("accepted\n")), TailBytes: len("accepted\n"), TailSHA256: hex.EncodeToString(sum[:])}
	read, err := readDeviceSignalChunk(path, cursor, 1<<20)
	if err != nil || string(read.data) != "unread\n" || read.fileID != oldID {
		t.Fatalf("protected old source was not recovered: %+v %v", read, err)
	}
	sum = sha256.Sum256(read.data)
	cursor.Offset, cursor.TailBytes, cursor.TailSHA256 = read.end, len(read.data), hex.EncodeToString(sum[:])
	read, err = readDeviceSignalChunk(path, cursor, 1<<20)
	if err != nil || string(read.data) != "successor\n" || !read.verifiedRotation || read.fileID != FileIdentityBirth(path, mustStat(t, path)) {
		t.Fatalf("protected successor was not recovered: %+v %v", read, err)
	}
}

func TestProtectedFlowAnchorRejectsUnprovedSuccessor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flow-syn.jsonl")
	recovery := filepath.Join(dir, "protected")
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(deviceSignalRecoveryDirEnv, recovery)
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	old := []byte("accepted\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	oldID := FileIdentityBirth(path, mustStat(t, path))
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path+".1", filepath.Join(recovery, "flow-syn.jsonl.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("real-next\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recovery, "flow-syn-live-unrelated.jsonl"), []byte("wrong-next\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(old)
	cursor := streamlog.SourceCursor{FileID: oldID, Offset: int64(len(old)), TailBytes: len(old), TailSHA256: hex.EncodeToString(sum[:])}
	if _, err := readDeviceSignalChunk(path, cursor, 1<<20); !errors.Is(err, ErrStreamSourceGap) {
		t.Fatalf("unproved protected successor must not be consumed: %v", err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestDeviceSignalCompressedRotationRejectsBadTailWithoutMovingCursor(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	old := []byte("first\nsecond\n")
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
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "existing-epoch", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), Offset: 6, TailBytes: 6, TailSHA256: hex.EncodeToString(make([]byte, 32)), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	writeGzipFixture(t, path+".1.gz", old)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, Source{Kind: "device-signals", Path: path})
	if !errors.Is(err, ErrStreamSourceGap) {
		t.Fatalf("unproven compressed rotation accepted: %v", err)
	}
	cursor, err := j.LoadSource("device-signals", path)
	if err != nil || cursor.Offset != 6 || cursor.Epoch != "existing-epoch" {
		t.Fatalf("failed proof moved cursor: %+v %v", cursor, err)
	}
}

func TestDeviceSignalCompressedRotationRequiresEveryIntermediateFile(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	recovery := filepath.Join(dir, "protected")
	t.Setenv("PROXY_SENTINEL_DEVICE_SIGNAL_RECOVERY_DIR", recovery)
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	line := func(id string) []byte {
		return []byte(`{"schema_version":"v1","event_id":"` + id + `","type":"device","timestamp":"2026-11-13T00:00:00Z","subject":{"ip":"192.0.2.8"}}` + "\n")
	}
	first, unread, later := line("first"), line("unread"), line("later")
	if err := os.WriteFile(path, append(append([]byte{}, first...), unread...), 0o600); err != nil {
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
	sum := sha256.Sum256(first)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "existing-epoch", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(sum[:]), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	writeGzipFixture(t, filepath.Join(recovery, "ttl.jsonl.3.gz"), append(append([]byte{}, first...), unread...))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recovery, "ttl.jsonl.1"), later, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, later, 0o600); err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "device-signals", Path: path}
	if _, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source); err != nil || !captured {
		t.Fatalf("old unread bytes were not captured: %t %v", captured, err)
	}
	before, err := j.LoadSource(source.Kind, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source); !errors.Is(err, ErrStreamSourceGap) || captured {
		t.Fatalf("missing .2 was skipped: captured=%t err=%v", captured, err)
	}
	after, err := j.LoadSource(source.Kind, path)
	if err != nil || after.Epoch != before.Epoch || after.FileID != before.FileID || after.Offset != before.Offset {
		t.Fatalf("gap moved cursor: before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestDeviceSignalCompressedRotationRejectsBrokenGzipTrailer(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	old := []byte("first\nsecond\n")
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
	sum := sha256.Sum256([]byte("first\n"))
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "existing-epoch", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), Offset: 6, TailBytes: 6, TailSHA256: hex.EncodeToString(sum[:]), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	archive := path + ".1.gz"
	writeGzipFixture(t, archive, old)
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x80
	if err := os.WriteFile(archive, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, Source{Kind: "device-signals", Path: path}); !errors.Is(err, ErrStreamSourceGap) || captured {
		t.Fatalf("broken gzip trailer accepted: captured=%t err=%v", captured, err)
	}
	cursor, err := j.LoadSource("device-signals", path)
	if err != nil || cursor.Offset != 6 {
		t.Fatalf("broken archive moved cursor: %+v %v", cursor, err)
	}
}

func TestDeviceSignalCompressedRotationReusesReaderAcrossProjectionSegments(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	line := func(id string) []byte {
		return []byte(`{"schema_version":"v1","event_id":"` + id + `","type":"device","timestamp":"2026-11-13T00:00:00Z","subject":{"ip":"192.0.2.8"}}` + "\n")
	}
	first := line("first")
	old := append([]byte{}, first...)
	for i := 0; i < 2025; i++ {
		old = append(old, line("unread-"+strconv.Itoa(i))...)
	}
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
	sum := sha256.Sum256(first)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "existing-epoch", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(sum[:]), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	writeGzipFixture(t, path+".1.gz", old)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, line("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "device-signals", Path: path}
	var firstInflater *signalGzipReader
	for index, want := range []int{1000, 1000, 25} {
		if index == 2 {
			clearSignalGzip(path)
			j, err = streamlog.Open(j.Directory())
			if err != nil {
				t.Fatal(err)
			}
		}
		id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a", MaxBatchBytes: 1 << 20}, source)
		if err != nil || !captured {
			t.Fatalf("segment %d: %s %t %v", index, id, captured, err)
		}
		state, err := j.Load(id)
		if err != nil || len(state.Segment.Events) != want {
			t.Fatalf("segment %d events=%d want=%d: %v", index, len(state.Segment.Events), want, err)
		}
		signalGzipState.Lock()
		inflater := signalGzipState.bySource[path]
		signalGzipState.Unlock()
		if index == 0 {
			firstInflater = inflater
			cursor, err := j.LoadSource(source.Kind, path)
			if err != nil {
				t.Fatal(err)
			}
			files, err := deviceSignalFiles(path)
			if err != nil {
				t.Fatal(err)
			}
			probeCalls := 0
			matches := matchingSignalCursorFiles(path, files, cursor, func(string, streamlog.SourceCursor) bool {
				probeCalls++
				return false
			})
			matched, ok := uniqueSignalMatch(matches)
			if probeCalls != 0 || !ok || !os.SameFile(matched.info, inflater.info) || matched.id == cursor.FileID {
				t.Fatalf("committed gzip cursor did not reuse its verified archive: probes=%d match=%+v ok=%t", probeCalls, matched, ok)
			}
		} else if index == 1 && inflater != firstInflater {
			t.Fatal("partial projection segment reinflated the whole archive")
		}
	}
	cursor, err := j.LoadSource(source.Kind, path)
	if err != nil || cursor.Offset != int64(len(old)) {
		t.Fatalf("compressed source not fully consumed: %+v %v", cursor, err)
	}
}

func writeGzipFixture(t *testing.T, path string, raw []byte) {
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
