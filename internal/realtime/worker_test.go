package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

func TestSharedDeviceSignalsUseTheNormalizedEventBoundary(t *testing.T) {
	event := normalized.Event{SchemaVersion: "v1", EventID: "device-shared-1", Source: "packet-sidecar", SourceEventType: "ttl", Type: "device", Timestamp: "2026-10-08T14:00:00Z", Observer: map[string]any{"sensor_id": "untrusted"}, Subject: map[string]any{"ip": "192.0.2.10"}, Payload: map[string]any{"ttl": 63, "tcp_stack": "mss=1460,ws=8,sack=true,ts=true,df=true,opt=2-4-8-1-3"}}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	events, stats, err := normalize(Source{Kind: "shared-device-signals"}, append(raw, '\n'), 0, "ncu-184-router-pilot", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || stats.Emitted != 1 || events[0].Observer["sensor_id"] != "ncu-184-router-pilot" {
		t.Fatalf("shared signal did not preserve the standard-event boundary: events=%+v stats=%+v", events, stats)
	}
}

func TestControlledFlowSYNIsAWeakStandardFlowEvent(t *testing.T) {
	event := normalized.Event{SchemaVersion: "v1", EventID: "flow-syn-test", Source: "flow-syn-sidecar", SourceEventType: "syn_attempt", Type: "flow", Timestamp: "2026-11-01T00:00:00Z", Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"ip": "10.202.4.8"}, Flow: map[string]any{"src_ip": "10.202.4.8", "proto": "tcp", "dst_port": 443}, Payload: map[string]any{"origin": "initial_syn", "connection_outcome": "unverified", "observed_count": 1}}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	events, stats, err := normalize(Source{Kind: "device-signals"}, append(raw, '\n'), 0, "sensor-a", nil)
	if err != nil || len(events) != 1 || stats.Emitted != 1 || events[0].Type != "flow" {
		t.Fatalf("flow SYN standard event rejected: events=%+v stats=%+v err=%v", events, stats, err)
	}
	event.Flow["src_ip"] = "10.202.4.9"
	forged, _ := json.Marshal(event)
	_, stats, err = normalize(Source{Kind: "device-signals"}, append(forged, '\n'), 0, "sensor-a", nil)
	if err != nil || stats.Skipped != 1 || stats.Emitted != 0 {
		t.Fatalf("mismatched source IP accepted: %+v err=%v", stats, err)
	}
	event.Flow["src_ip"] = "10.202.4.8"
	event.EventID = "flow-syn-ack-test"
	event.SourceEventType = "syn_ack_observed"
	event.Payload["connection_outcome"] = "syn_ack_observed"
	event.Payload["origin"] = "matched_reverse_syn_ack"
	response, _ := json.Marshal(event)
	events, stats, err = normalize(Source{Kind: "device-signals"}, append(response, '\n'), 0, "sensor-a", nil)
	if err != nil || len(events) != 1 || stats.Emitted != 1 {
		t.Fatalf("matched response event rejected: events=%+v stats=%+v err=%v", events, stats, err)
	}
	event.Payload["connection_outcome"] = "open"
	forged, _ = json.Marshal(event)
	_, stats, err = normalize(Source{Kind: "device-signals"}, append(forged, '\n'), 0, "sensor-a", nil)
	if err != nil || stats.Skipped != 1 {
		t.Fatalf("overstated response accepted: %+v err=%v", stats, err)
	}
}

type fakeBackend struct {
	checkpoint    ingest.Checkpoint
	found         bool
	events        []normalized.Event
	batches       []ingest.Batch
	diagnostics   []ingest.Diagnostic
	failedBatches int
	writeEventErr error
	writeRunErr   error
	writeDiagErr  error
	commitErr     error
}

func (f *fakeBackend) WriteCollectorRun(context.Context, store.Run) error { return f.writeRunErr }
func (f *fakeBackend) WriteNormalizedEvents(_ context.Context, events []normalized.Event) error {
	if f.writeEventErr != nil {
		return f.writeEventErr
	}
	f.events = append(f.events, events...)
	return nil
}
func (f *fakeBackend) WriteIngestDiagnostics(_ context.Context, items []ingest.Diagnostic) error {
	if f.writeDiagErr != nil {
		return f.writeDiagErr
	}
	f.diagnostics = append(f.diagnostics, items...)
	return nil
}
func (f *fakeBackend) LoadIngestCheckpoint(context.Context, string, string) (ingest.Checkpoint, bool, error) {
	return f.checkpoint, f.found, nil
}
func (f *fakeBackend) BeginIngestBatch(_ context.Context, item ingest.Batch) error {
	f.batches = append(f.batches, item)
	return nil
}
func (f *fakeBackend) CommitIngestBatch(_ context.Context, item ingest.Batch, _ string) error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.checkpoint = ingest.Checkpoint{Offset: item.EndOffset, FileID: item.FileID}
	f.found = true
	return nil
}
func (f *fakeBackend) FailIngestBatch(context.Context, string, error) error {
	f.failedBatches++
	return nil
}

func TestProcessOnceCommitsOnlyCompleteLinesAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	line := `{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}`
	if err := os.WriteFile(path, []byte(line+"\n"+line), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	opts := Options{SensorID: "sensor-a", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
	if err := ProcessOnce(context.Background(), backend, opts, Source{Kind: "suricata", Path: path}); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 1 {
		t.Fatalf("expected one complete event, got %d", len(backend.events))
	}
	firstOffset := backend.checkpoint.Offset
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err := ProcessOnce(context.Background(), backend, opts, Source{Kind: "suricata", Path: path}); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 2 || backend.checkpoint.Offset <= firstOffset {
		t.Fatalf("resume failed: events=%d offset=%d", len(backend.events), backend.checkpoint.Offset)
	}
}

func TestProcessOnceUsesStableIDsAfterCheckpointReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	line := `{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	opts := Options{SensorID: "sensor-a", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
	if err := ProcessOnce(context.Background(), backend, opts, Source{Kind: "suricata", Path: path}); err != nil {
		t.Fatal(err)
	}
	firstID := backend.events[0].EventID
	backend.checkpoint.Offset = 0
	if err := ProcessOnce(context.Background(), backend, opts, Source{Kind: "suricata", Path: path}); err != nil {
		t.Fatal(err)
	}
	if backend.events[1].EventID != firstID {
		t.Fatalf("replay id changed: %s != %s", backend.events[1].EventID, firstID)
	}
}

func TestReadCompleteLinesResetsOffsetAfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte("old-one\nold-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := ingest.Checkpoint{FileID: fileIdentity(path, info), Offset: 8}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("new-one\nnew-two\nnew-three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}

	data, newID, start, end, rotated, err := readCompleteLines(path, checkpoint, true, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !rotated || start != 0 || end != int64(len(data)) {
		t.Fatalf("rotation was not reset: rotated=%t start=%d end=%d", rotated, start, end)
	}
	if newID == checkpoint.FileID || string(data) != "new-one\nnew-two\nnew-three\n" {
		t.Fatalf("unexpected replacement read: id=%q data=%q", newID, data)
	}
}

func TestReadSourceChunkDrainsDateExtRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ttl.jsonl")
	old := "{\"bucket\":\"a\"}\n{\"bucket\":\"b\"}\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The reader already consumed the first record and logrotate renamed the file
	// with a date suffix instead of the plain ".1" name.
	checkpoint := ingest.Checkpoint{FileID: fileIdentity(path, info), Offset: int64(len("{\"bucket\":\"a\"}\n"))}
	rotated := filepath.Join(dir, "ttl.jsonl-20261015")
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\"bucket\":\"c\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	read, err := readSourceChunk(path, checkpoint, true, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if !read.archive {
		t.Fatalf("dateext rotation was not drained: archive=%t data=%q", read.archive, read.data)
	}
	if string(read.data) != "{\"bucket\":\"b\"}\n" || read.start != checkpoint.Offset {
		t.Fatalf("unexpected archive read: start=%d data=%q", read.start, read.data)
	}
	if err := os.Remove(rotated); err != nil {
		t.Fatal(err)
	}
	read, err = readSourceChunk(path, checkpoint, true, 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	if !read.truncated || read.start != 0 || string(read.data) != "{\"bucket\":\"c\"}\n" {
		t.Fatalf("missing archive did not fall back to a fresh file: truncated=%t start=%d data=%q", read.truncated, read.start, read.data)
	}
}

func TestProcessOnceRetriesStableBatchAfterPostEventFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	line := `{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{writeRunErr: errors.New("postgres temporarily unavailable")}
	opts := Options{SensorID: "fault-sensor", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
	if err := ProcessOnce(context.Background(), backend, opts, Source{Kind: "suricata", Path: path}); err == nil {
		t.Fatal("expected the post-event write to fail")
	}
	if backend.found || backend.failedBatches != 1 {
		t.Fatalf("failed batch advanced checkpoint: found=%t failures=%d", backend.found, backend.failedBatches)
	}
	backend.writeRunErr = nil
	if err := ProcessOnce(context.Background(), backend, opts, Source{Kind: "suricata", Path: path}); err != nil {
		t.Fatal(err)
	}
	if len(backend.batches) != 2 || backend.batches[0].BatchID != backend.batches[1].BatchID {
		t.Fatalf("retry did not preserve batch identity: %+v", backend.batches)
	}
	if len(backend.events) != 2 || backend.events[0].EventID != backend.events[1].EventID {
		t.Fatalf("retry did not preserve event identity: %+v", backend.events)
	}
	if !backend.found || backend.checkpoint.Offset != int64(len(line)) {
		t.Fatalf("successful retry did not commit checkpoint: %+v", backend.checkpoint)
	}
}

type stagedDiscoveryRecoveryBackend struct {
	fakeBackend
	staged []ingest.Batch
	ids    []string
}

func (f *stagedDiscoveryRecoveryBackend) StageDiscoveryBatch(_ context.Context, batch ingest.Batch, events []normalized.Event) error {
	f.staged = append(f.staged, batch)
	for _, event := range events {
		f.ids = append(f.ids, event.EventID)
	}
	return nil
}

func TestProcessOnceReplaysStagedDiscoveryAfterCheckpointCommitFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dhcp.log")
	line := `{"ts":1792890000,"uid":"C-replay","xid":707,"capture_vlan":"42","mac":"02:00:00:00:00:10","assigned_addr":"192.0.2.82","msg_types":"ACK"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("checkpoint transaction failed after ClickHouse accepted the event")
	backend := &stagedDiscoveryRecoveryBackend{fakeBackend: fakeBackend{commitErr: cause}}
	opts := Options{SensorID: "campus-204", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}
	source := Source{Kind: "zeek-dhcp-binding", Path: path}
	if err := ProcessOnce(context.Background(), backend, opts, source); !errors.Is(err, cause) {
		t.Fatalf("expected checkpoint failure, got %v", err)
	}
	if backend.found || len(backend.staged) != 1 || len(backend.events) != 1 {
		t.Fatalf("source advanced or discovery was not staged before failure: %+v", backend)
	}
	backend.commitErr = nil
	if err := ProcessOnce(context.Background(), backend, opts, source); err != nil {
		t.Fatal(err)
	}
	if len(backend.staged) != 2 || backend.staged[0].BatchID != backend.staged[1].BatchID || len(backend.ids) != 2 || backend.ids[0] != backend.ids[1] || !backend.found || backend.checkpoint.Offset != int64(len(line)) {
		t.Fatalf("replay did not preserve source batch and selected event identity: staged=%+v ids=%v checkpoint=%+v", backend.staged, backend.ids, backend.checkpoint)
	}
}

func TestProcessOnceKeepsCheckpointWhenEventStorageUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	line := `{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{writeEventErr: errors.New("clickhouse temporarily unavailable")}
	if err := ProcessOnce(context.Background(), backend, Options{SensorID: "fault-sensor", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}, Source{Kind: "suricata", Path: path}); err == nil {
		t.Fatal("expected event storage failure")
	}
	if backend.found || len(backend.events) != 0 || backend.failedBatches != 1 {
		t.Fatalf("event storage failure was not isolated: found=%t events=%d failures=%d", backend.found, len(backend.events), backend.failedBatches)
	}
}

func TestProcessOnceIsolatesMalformedLinesAndCommitsGoodEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	valid := `{"timestamp":"2026-07-22T10:00:00Z","event_type":"dns","src_ip":"10.0.0.2","dest_ip":"1.1.1.1","proto":"UDP","dns":{"rrname":"example.test"}}`
	data := valid + "\n{not-json}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	if err := ProcessOnce(context.Background(), backend, Options{SensorID: "bad-line-sensor", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}, Source{Kind: "suricata", Path: path}); err != nil {
		t.Fatal(err)
	}
	if len(backend.events) != 1 || len(backend.diagnostics) != 1 || backend.diagnostics[0].Counters["malformed"] != 1 {
		t.Fatalf("malformed line was not isolated: events=%d diagnostics=%+v", len(backend.events), backend.diagnostics)
	}
	if backend.checkpoint.Offset != int64(len(data)) {
		t.Fatalf("batch with isolated bad line was not committed: %+v", backend.checkpoint)
	}
}
