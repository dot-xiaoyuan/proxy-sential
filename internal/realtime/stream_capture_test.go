package realtime

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/streamlog"
)

const streamSuricataLine = `{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}` + "\n"

func startStreamFixture(t *testing.T, path string, offset int64) *streamlog.Journal {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "suricata", Path: path, FileID: fileIdentity(path, info), Offset: offset, ParserVersion: "suricata-v1"}); err != nil {
		t.Fatal(err)
	}
	return j
}

func TestStreamCaptureStartsAtAuditedFreshOffsetAndRecoversPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(streamSuricataLine), 0o600); err != nil {
		t.Fatal(err)
	}
	j := startStreamFixture(t, path, int64(len(streamSuricataLine)))
	source := Source{Kind: "suricata", Path: path}
	opts := Options{SensorID: "sensor-a"}
	if id, captured, err := CaptureStreamOnce(context.Background(), j, opts, source); err != nil || captured || id != "" {
		t.Fatalf("old input was captured: %s %t %v", id, captured, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(streamSuricataLine); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	id, captured, err := CaptureStreamOnce(context.Background(), j, opts, source)
	if err != nil || !captured {
		t.Fatalf("fresh input was not captured: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Segment.StartOffset != int64(len(streamSuricataLine)) || len(state.Segment.Events) != 1 || string(state.Segment.Raw) != streamSuricataLine {
		t.Fatalf("bad durable segment: %+v", state.Segment)
	}
	cursor, err := j.LoadSource(source.Kind, source.Path)
	if err != nil || cursor.Offset != int64(2*len(streamSuricataLine)) {
		t.Fatalf("source not committed after segment: %+v %v", cursor, err)
	}
	j, err = streamlog.Open(j.Directory())
	if err != nil {
		t.Fatal(err)
	}
	ids, err := j.PendingSegments()
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("pending recovery: %v %v", ids, err)
	}
}

func TestStreamCaptureOffersDurableSegmentBeforeCursorCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(streamSuricataLine), 0o600); err != nil {
		t.Fatal(err)
	}
	j := startStreamFixture(t, path, 0)
	source := Source{Kind: "suricata", Path: path}
	called := false
	id, captured, err := captureStreamOnceWithReady(context.Background(), j, Options{SensorID: "sensor-a"}, source, func(readyID string) error {
		called = true
		state, err := j.Load(readyID)
		if err != nil || !state.ProcessingReady || state.Committed {
			t.Fatalf("segment is not durably ready before cursor: %+v %v", state, err)
		}
		cursor, err := j.LoadSource(source.Kind, source.Path)
		if err != nil || cursor.LastSegmentID != "" || cursor.Offset != 0 {
			t.Fatalf("cursor advanced before lanes could start: %+v %v", cursor, err)
		}
		return j.BeginAttempt(readyID, streamlog.Archive)
	})
	if err != nil || !captured || !called {
		t.Fatalf("source was not staged before cursor: id=%s captured=%t callback=%t err=%v", id, captured, called, err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Committed || state.Acks[streamlog.Archive] != streamlog.Attempted {
		t.Fatalf("attempt was lost during source commit: %+v %v", state, err)
	}
}

func TestStreamCaptureStopsWhenUnreadRotatedFileIsMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(streamSuricataLine), 0o600); err != nil {
		t.Fatal(err)
	}
	j := startStreamFixture(t, path, 0)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(streamSuricataLine), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, Source{Kind: "suricata", Path: path})
	if !errors.Is(err, ErrStreamSourceGap) {
		t.Fatalf("missing unread file was accepted: %v", err)
	}
}

func TestStreamCaptureRecordsHeaderOnlyInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
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
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "zeek-dhcp", Path: path, FileID: fileIdentity(path, info), Offset: 0, ParserVersion: "zeek-v1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#separator \\x09\n#path dhcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, Source{Kind: "zeek-dhcp", Path: path})
	if err != nil || !captured {
		t.Fatalf("header-only input not captured: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil || len(state.Segment.Events) != 0 || state.Acks[streamlog.Archive] != streamlog.NotApplicable {
		t.Fatalf("header-only state: %+v %v", state, err)
	}
}

func TestStreamCaptureBoundsLargeInputByWholeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	j := startStreamFixture(t, path, 0)
	if err := os.WriteFile(path, []byte(strings.Repeat(streamSuricataLine, 1400)), 0o600); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a", MaxBatchBytes: 1 << 20}, Source{Kind: "suricata", Path: path})
	if err != nil || !captured {
		t.Fatalf("capture failed: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Segment.Events) != streamlog.MaxSegmentEvents || state.Segment.EndOffset >= int64(1400*len(streamSuricataLine)) {
		t.Fatalf("segment did not bound input: %d events, offset %d", len(state.Segment.Events), state.Segment.EndOffset)
	}
}

func TestStreamCaptureBoundsDHCPProjectionToFiftyRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.log")
	line := `{"ts":1792890000,"client_addr":"192.0.2.82","mac":"02:00:00:00:00:82","assigned_addr":"192.0.2.82","msg_types":["ACK"]}` + "\n"
	if err := os.WriteFile(path, []byte(strings.Repeat(line, 120)), 0o600); err != nil {
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
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "zeek-dhcp", Path: path, FileID: fileIdentity(path, info), ParserVersion: "zeek-v1"}); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, Source{Kind: "zeek-dhcp", Path: path})
	if err != nil || !captured {
		t.Fatalf("DHCP capture failed: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil || len(state.Segment.Events) != 50 || state.Segment.EndOffset != int64(50*len(line)) {
		t.Fatalf("DHCP projection segment was not bounded: events=%d end=%d err=%v", len(state.Segment.Events), state.Segment.EndOffset, err)
	}
}

func TestStreamCaptureDHCPBindingKeepsVerifiedPositionAndBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_dhcp_binding.log")
	line := `{"ts":1792890000,"uid":"C1","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n"
	if err := os.WriteFile(path, []byte(strings.Repeat(line, 120)), 0o600); err != nil {
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
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-binding", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), ParserVersion: "zeek-dhcp-binding-v1"}); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if err != nil || !captured {
		t.Fatalf("verified DHCP binding capture failed: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil || len(state.Segment.Events) != 50 || state.Segment.EndOffset != int64(50*len(line)) {
		t.Fatalf("verified DHCP binding bound failed: events=%d end=%d err=%v", len(state.Segment.Events), state.Segment.EndOffset, err)
	}
	if got := state.Segment.Events[0].Payload["msg_types"]; got != "ACK" {
		t.Fatalf("verified binding action was not parsed: %v", got)
	}
}

func TestStreamCaptureDHCPBindingOffersSourceBackedBodyBeforeCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_dhcp_binding.log")
	raw := []byte(`{"ts":1792890000,"uid":"C1","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
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
	j.SetRawResolver(func(streamlog.Segment) ([]byte, error) { return append([]byte(nil), raw...), nil })
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-binding", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), ParserVersion: "zeek-dhcp-binding-v1"}); err != nil {
		t.Fatal(err)
	}
	called := false
	id, captured, err := captureStreamOnceWithReady(context.Background(), j, Options{SensorID: "sensor-a"}, source, func(readyID string) error {
		called = true
		state, err := j.Load(readyID)
		if err != nil || !state.ProcessingReady || state.Committed || !state.Segment.SourceBackedRaw {
			t.Fatalf("DHCP descriptor was not ready before cursor: %+v %v", state, err)
		}
		cursor, err := j.LoadSource(source.Kind, source.Path)
		if err != nil || cursor.Offset != 0 || cursor.LastSegmentID != "" {
			t.Fatalf("DHCP cursor moved before sink was offered: %+v %v", cursor, err)
		}
		return j.BeginAttempt(readyID, streamlog.Archive)
	})
	if err != nil || !captured || !called {
		t.Fatalf("DHCP segment was not offered before cursor: %s %t %t %v", id, captured, called, err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Committed || state.ProcessingReady || state.Acks[streamlog.Archive] != streamlog.Attempted {
		t.Fatalf("DHCP cursor commit lost attempted sink: %+v %v", state, err)
	}
}

func TestStreamCaptureDrainsVerifiedCompressedZeekRotation(t *testing.T) {
	dir := t.TempDir()
	currentDir := filepath.Join(dir, "current")
	archiveDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(currentDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(currentDir, "device_dhcp_binding.log")
	line := func(uid string) []byte {
		return []byte(`{"ts":1792890000,"uid":"` + uid + `","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n")
	}
	first, second, third := line("C1"), line("C2"), line("C3")
	if err := os.WriteFile(path, append(append([]byte(nil), first...), second...), 0o600); err != nil {
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
	hash := sha256.Sum256(first)
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-binding", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(hash[:]), ParserVersion: "zeek-dhcp-binding-v1"}); err != nil {
		t.Fatal(err)
	}
	archived := filepath.Join(archiveDir, "device_dhcp_binding.12:00:00-13:00:00.log.gz")
	f, err := os.Create(archived)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(append(append([]byte(nil), first...), second...)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, third, 0o600); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if err != nil || !captured {
		t.Fatalf("archive tail not captured: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(state.Segment.Raw) != string(second) || state.Segment.FileID != fileIdentity(path, info) {
		t.Fatalf("wrong archived bytes: %+v", state.Segment)
	}
	id, captured, err = CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if err != nil || !captured {
		t.Fatalf("new file not captured after archive: %s %t %v", id, captured, err)
	}
	state, err = j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if string(state.Segment.Raw) != string(third) || state.Segment.StartOffset != 0 || state.Segment.PreviousOffset != int64(len(first)+len(second)) {
		t.Fatalf("rotation skipped or repeated data: %+v", state.Segment)
	}
}

func TestStreamBindingReferenceSurvivesRestartAndCompressedRotation(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current")
	archive := filepath.Join(dir, time.Now().Format("2006-01-02"))
	for _, path := range []string{current, archive} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(current, "device_dhcp_binding.log")
	raw := []byte(`{"ts":1792890000,"uid":"C1","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
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
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-binding", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), ParserVersion: "zeek-dhcp-binding-v1"}); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if err != nil || !captured {
		t.Fatalf("capture reference: %s %t %v", id, captured, err)
	}
	descriptor, err := os.ReadFile(filepath.Join(journalDir, id+".segment"))
	if err != nil || bytes.Contains(descriptor, []byte(`"raw":`)) || !bytes.Contains(descriptor, []byte(`"source_backed_raw":true`)) {
		t.Fatalf("source bytes copied into journal: %v %s", err, descriptor)
	}
	if _, err := os.Stat(filepath.Join(journalDir, id+".acklog")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("capture created an empty ack log: %v", err)
	}
	archived := filepath.Join(archive, "device_dhcp_binding.12:00:00-13:00:00.log.gz")
	f, err := os.Create(archived)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err = zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#new file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err = streamlog.Open(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	j.SetRawResolver(resolveZeekSourceRaw)
	recovered, err := j.RecoverSource(source.Kind, path)
	if err != nil || len(recovered) != 1 || recovered[0] != id {
		t.Fatalf("recover rotated reference: %v %v", recovered, err)
	}
	state, err := j.Load(id)
	if err != nil || !bytes.Equal(state.Segment.Raw, raw) || !state.Committed {
		t.Fatalf("rehydrate rotated source bytes: %v %+v", err, state)
	}
}

func TestStreamCaptureDoesNotSkipUnverifiedZeekRotation(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current")
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(current, "device_dhcp_binding.log")
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
	hash := sha256.Sum256(old)
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-binding", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), Offset: int64(len(old)), TailBytes: len(old), TailSHA256: hex.EncodeToString(hash[:]), ParserVersion: "zeek-dhcp-binding-v1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if !errors.Is(err, ErrStreamArchivePending) {
		t.Fatalf("unverified rotation skipped: %v", err)
	}
}

func TestZeekBindingDetectsReusedInodeWithDifferentCommittedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "current", "device_dhcp_binding.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	old := []byte("old-first-record\n")
	if err := os.WriteFile(path, append(append([]byte(nil), old...), []byte("old-second-record\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(old)
	cursor := streamlog.SourceCursor{FileID: fileIdentity(path, info), Offset: int64(len(old)), TailBytes: len(old), TailSHA256: hex.EncodeToString(sum[:])}
	if err := os.WriteFile(path, []byte("new-first-record\nnew-second-record\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(path)
	if err != nil || fileIdentity(path, current) != cursor.FileID {
		t.Fatalf("fixture did not reuse file identity: %v", err)
	}
	if _, err := readZeekBindingChunk(path, cursor, 1<<20); !errors.Is(err, ErrStreamArchivePending) {
		t.Fatalf("reused inode was accepted as the old file: %v", err)
	}
}

func TestZeekBindingRawResolverSearchesArchiveAfterInodeReuse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current", "device_dhcp_binding.log")
	archiveDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
	for _, directory := range []string{filepath.Dir(path), archiveDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := []byte("old-first-record\nold-second-record\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	sum := sha256.Sum256(old)
	segment := streamlog.Segment{Source: "zeek-dhcp-binding", SourceBackedRaw: true, SourcePath: path, FileID: fileIdentity(path, info), StartOffset: 0, EndOffset: int64(len(old)), RawSHA256: hex.EncodeToString(sum[:])}
	archivePath := filepath.Join(archiveDir, "device_dhcp_binding.12:00:00-13:00:00.log.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(old); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Zeek can reuse the inode while the replacement is still shorter than
	// the old segment's offset. The rotated archive remains authoritative.
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveZeekSourceRaw(segment)
	if err != nil || !bytes.Equal(resolved, old) {
		t.Fatalf("archived bytes were not recovered after inode reuse: %v", err)
	}
}

func TestZeekBindingPositionKeyIncludesFileGeneration(t *testing.T) {
	source := Source{Kind: "zeek-dhcp-binding", Path: "/logs/current/device_dhcp_binding.log"}
	key := func(generation uint64) string {
		events := []normalized.Event{{EventID: "producer-id"}}
		if err := assignStreamPositionKeys(events, source, "fresh-v2", "reused-inode", 0, []byte("same-position\n"), generation); err != nil {
			t.Fatal(err)
		}
		return events[0].EventID
	}
	if first, second := key(1), key(2); first == second || first != key(1) {
		t.Fatalf("file generations share an unstable event key: %q %q", first, second)
	}
}

func TestZeekBindingV2RecoversArchiveWhenCurrentReusesInode(t *testing.T) {
	dir := t.TempDir()
	currentDir := filepath.Join(dir, "current")
	archiveDir := filepath.Join(dir, time.Now().Format("2006-01-02"))
	for _, directory := range []string{currentDir, archiveDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(currentDir, "device_dhcp_binding.log")
	line := func(uid string) []byte {
		return []byte(`{"ts":1792890000,"uid":"` + uid + `","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n")
	}
	first, second, third := line("C1"), line("C2"), line("C3")
	old := append(append([]byte(nil), first...), second...)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	sum := sha256.Sum256(first)
	j, err := streamlog.Open(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-v2", Source: source.Kind, Path: path, FileID: fileIdentity(path, info), Offset: int64(len(first)), TailBytes: len(first), TailSHA256: hex.EncodeToString(sum[:]), ParserVersion: "zeek-dhcp-binding-v2", KeyScheme: "generation-v2", Generation: 1}); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(archiveDir, "device_dhcp_binding.12:00:00-13:00:00.log.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write(old); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, third, 0o600); err != nil {
		t.Fatal(err)
	}
	current, _ := os.Stat(path)
	if fileIdentity(path, current) != fileIdentity(path, info) {
		t.Fatal("fixture did not reuse inode")
	}
	var keys []string
	for _, wantGeneration := range []uint64{1, 2} {
		id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
		if err != nil || !captured {
			t.Fatalf("generation %d capture: %v", wantGeneration, err)
		}
		state, err := j.Load(id)
		if err != nil || state.Segment.SourceGeneration != wantGeneration || len(state.Segment.Events) != 1 {
			t.Fatalf("generation %d state: %+v %v", wantGeneration, state.Segment, err)
		}
		keys = append(keys, state.Segment.Events[0].EventID)
	}
	if keys[0] == keys[1] {
		t.Fatal("reused inode collapsed two generations")
	}
}

func TestStreamCaptureGivesIdenticalRecordsDistinctStablePositionKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(strings.Repeat(streamSuricataLine, 2)), 0o600); err != nil {
		t.Fatal(err)
	}
	j := startStreamFixture(t, path, 0)
	source := Source{Kind: "suricata", Path: path}
	opts := Options{SensorID: "sensor-a"}
	id, captured, err := CaptureStreamOnce(context.Background(), j, opts, source)
	if err != nil || !captured {
		t.Fatalf("capture identical records: %s %t %v", id, captured, err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Segment.Events) != 2 || state.Segment.Events[0].EventID == state.Segment.Events[1].EventID {
		t.Fatalf("identical records collapsed: %+v", state.Segment.Events)
	}
	if state.Segment.Events[0].RawRef["source_offset"] != float64(0) || state.Segment.Events[1].RawRef["source_offset"] != float64(len(streamSuricataLine)) {
		t.Fatalf("source offsets not preserved: %+v", state.Segment.Events)
	}
	if _, _, err := CaptureStreamOnce(context.Background(), j, opts, source); err != nil {
		t.Fatal(err)
	}
	loaded, err := j.Load(id)
	if err != nil || loaded.Segment.Events[0].EventID != state.Segment.Events[0].EventID || loaded.Segment.Events[1].EventID != state.Segment.Events[1].EventID {
		t.Fatalf("position keys changed after retry: %+v %v", loaded.Segment.Events, err)
	}
}

func TestStreamPositionKeysKeepSignedSuricataDerivedEvent(t *testing.T) {
	cfg, err := proxyprotocol.Load("../../examples/proxy-protocol/producers.example.json")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"timestamp":"2026-09-11T01:00:00Z","flow_id":123,"tx_id":0,"event_type":"http","src_ip":"192.0.2.1","dest_ip":"198.51.100.1","http":{"http_method":"CONNECT","status":200}}` + "\n")
	source := Source{Kind: "suricata", Path: "/logs/eve.json", CollectorInstanceID: "replay-boot", ProxyProducer: cfg.Producer("replay", "suricata", "replay-boot")}
	events, _, err := normalize(source, raw, 0, "replay", nil)
	if err != nil || len(events) != 2 {
		t.Fatalf("normalize proxy source: %d %v", len(events), err)
	}
	if err := assignStreamPositionKeys(events, source, "fresh", "file-1", 0, raw); err != nil {
		t.Fatal(err)
	}
	if events[0].EventID == events[1].EventID || events[0].RawRef["source_offset"] != int64(0) || events[1].RawRef["source_offset"] != int64(0) {
		t.Fatalf("derived events lack distinct source-position keys: %+v", events)
	}
	if result := proxyprotocol.Evaluate(events[1], cfg); !result.Trusted {
		t.Fatalf("stream position mutation invalidated proxy signature: %+v", result)
	}
}

func TestStreamPositionKeysKeepSignedZeekProxyEvents(t *testing.T) {
	cfg, err := proxyprotocol.Load("../../examples/proxy-protocol/producers.example.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../examples/proxy-protocol/zeek-replay.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "zeek-proxy", Path: "/logs/proxy_transactions.log", CollectorInstanceID: "replay-boot", ProxyProducer: cfg.Producer("replay", "zeek", "replay-boot")}
	events, _, err := normalize(source, raw, 0, "replay", nil)
	if err != nil || len(events) != 14 {
		t.Fatalf("normalize Zeek proxy log: %d %v", len(events), err)
	}
	if err := assignStreamPositionKeys(events, source, "fresh", "file-1", 0, raw); err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if result := proxyprotocol.Evaluate(event, cfg); !result.Trusted {
			t.Fatalf("stream position mutation invalidated Zeek proxy signature: %+v", result)
		}
	}
}

func TestStreamCaptureDoesNotAdvancePastRejectedStandardEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
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
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), Offset: 0, ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"v1","event_id":"bad","type":"risk"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, Source{Kind: "device-signals", Path: path})
	if err == nil || captured {
		t.Fatalf("rejected event was committed: captured=%t err=%v", captured, err)
	}
	state, err := j.Load(id)
	if err != nil || !state.Segment.Quarantined || string(state.Segment.Raw) != `{"schema_version":"v1","event_id":"bad","type":"risk"}`+"\n" {
		t.Fatalf("rejected original not isolated: %+v %v", state, err)
	}
	if err := (streamlog.Processor{Journal: j, Writer: &captureNoopWriter{}}).Drain(context.Background(), id); !errors.Is(err, streamlog.ErrQuarantined) {
		t.Fatalf("quarantine was drained: %v", err)
	}
	if err := j.Release(id); !errors.Is(err, streamlog.ErrQuarantined) {
		t.Fatalf("quarantine was released: %v", err)
	}
	if err := j.CommitSource("device-signals", path, id); !errors.Is(err, streamlog.ErrQuarantined) {
		t.Fatalf("quarantine advanced cursor: %v", err)
	}
	cursor, err := j.LoadSource("device-signals", path)
	if err != nil || cursor.Offset != 0 {
		t.Fatalf("rejected event advanced source: %+v %v", cursor, err)
	}
}

type captureNoopWriter struct{}

func TestControlledDeviceSignalRequiresOriginalMatchingScope(t *testing.T) {
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "ttl-owner", CampusID: "campus-a", AccessDomain: "bond0", InterfaceName: "bond0", ValidFrom: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC), ValidUntil: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)}
	event := normalized.Event{SchemaVersion: "v1", EventID: "device-1", Type: "device", Timestamp: "2026-10-25T04:00:00Z", Observer: map[string]any{"sensor_id": "sensor-a", "collector_instance_id": "ttl-owner", "interface": "bond0"}, Subject: map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"origin": "ttl"}}
	event = scope.Apply(event)
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateControlledStreamSignals(append(raw, '\n'), []normalized.Event{event}, scope, "bond0"); err != nil {
		t.Fatal(err)
	}
	unscoped := event
	unscoped.Observer = map[string]any{"sensor_id": "sensor-a"}
	raw, _ = json.Marshal(unscoped)
	if err := validateControlledStreamSignals(append(raw, '\n'), []normalized.Event{unscoped}, scope, "bond0"); err == nil {
		t.Fatal("unscoped router probe was accepted")
	}
	withoutEmbeddedInterface := *scope
	withoutEmbeddedInterface.InterfaceName = ""
	legacyControlled := withoutEmbeddedInterface.Apply(event)
	raw, _ = json.Marshal(legacyControlled)
	if err := validateControlledStreamSignals(append(raw, '\n'), []normalized.Event{legacyControlled}, &withoutEmbeddedInterface, "bond0"); err != nil {
		t.Fatalf("explicitly controlled interface was rejected: %v", err)
	}
}

func TestControlledDeviceSignalCaptureBoundsProjectionSegmentAtFiveHundred(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signals.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-device", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "signal-owner", CampusID: "campus-a", AccessDomain: "bond0", InterfaceName: "bond0", ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
	var input bytes.Buffer
	for i := 0; i < 525; i++ {
		event := normalized.Event{SchemaVersion: "v1", EventID: "signal-" + strconv.Itoa(i), Source: "device-signals", SourceEventType: "ssdp", Type: "device", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor-a", "collector_instance_id": "signal-owner", "interface": "bond0"}, Subject: map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"origin": "ssdp"}}
		if err := json.NewEncoder(&input).Encode(scope.Apply(event)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, input.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "device-signals", Path: path, CaptureScope: scope, ControlledInterface: "bond0"}
	for _, want := range []int{500, 25} {
		id, captured, err := CaptureStreamOnce(context.Background(), journal, Options{SensorID: "sensor-a"}, source)
		if err != nil || !captured {
			t.Fatalf("capture signal segment: id=%s captured=%t err=%v", id, captured, err)
		}
		state, err := journal.Load(id)
		if err != nil || len(state.Segment.Events) != want || !state.Segment.RawIsStandardEvents {
			t.Fatalf("segment events=%d, standard-source=%t, want %d: %v", len(state.Segment.Events), state.Segment.RawIsStandardEvents, want, err)
		}
	}
}

func TestControlledNonProjectionSignalsUseOneClickHouseBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handshake.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := streamlog.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-handshake", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "signal-owner", CampusID: "campus-a", AccessDomain: "bond0", InterfaceName: "bond0", ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
	var input bytes.Buffer
	for i := 0; i < 75; i++ {
		event := normalized.Event{SchemaVersion: "v1", EventID: "signal-" + strconv.Itoa(i), Source: "handshake-sidecar", SourceEventType: "handshake", Type: "device", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor-a", "collector_instance_id": "signal-owner", "interface": "bond0"}, Subject: map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"access_domain": "bond0"}}
		if err := json.NewEncoder(&input).Encode(scope.Apply(event)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, input.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), journal, Options{SensorID: "sensor-a"}, Source{Kind: "device-signals", Path: path, CaptureScope: scope, ControlledInterface: "bond0"})
	if err != nil || !captured {
		t.Fatalf("capture handshake batch: id=%s captured=%t err=%v", id, captured, err)
	}
	state, err := journal.Load(id)
	if err != nil || len(state.Segment.Events) != 75 || state.Segment.NeedsProjection {
		t.Fatalf("non-projected ClickHouse batch events=%d projection=%t err=%v", len(state.Segment.Events), state.Segment.NeedsProjection, err)
	}
}

func TestStreamProjectsOnlySelectedDiscoverySignals(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want bool
	}{{"ssdp", true}, {"dhcp", true}, {"http", true}, {"handshake", false}, {"capture_coverage", false}} {
		if got := needsStreamProjection([]normalized.Event{{Type: "device", SourceEventType: tc.kind}}); got != tc.want {
			t.Fatalf("source event %s projection=%t want %t", tc.kind, got, tc.want)
		}
	}
}

func (*captureNoopWriter) WriteBody(context.Context, string, streamlog.Segment) error     { return nil }
func (*captureNoopWriter) ReconcileBody(context.Context, string, streamlog.Segment) error { return nil }
func (*captureNoopWriter) WriteSearch(context.Context, string, streamlog.Segment) error   { return nil }
func (*captureNoopWriter) ReconcileSearch(context.Context, string, streamlog.Segment) error {
	return nil
}
func (*captureNoopWriter) Project(context.Context, string, streamlog.Segment) error { return nil }
func (*captureNoopWriter) ReconcileProjection(context.Context, string, streamlog.Segment) error {
	return nil
}
