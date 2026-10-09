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
