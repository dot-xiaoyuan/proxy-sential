package realtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestDeviceSignalDatedRotationResumesThroughVerifiedNumberedFiles(t *testing.T) {
	fixture := setupDeviceSignalRotationBridge(t)
	initial := fixture.read(t, fixture.path, 0, fixture.first)
	if initial.Offset != int64(len(fixture.first)) {
		t.Fatalf("first commit offset = %d", initial.Offset)
	}

	// While the reader is stopped, the original inode leaves the active name.
	fixture.rotate(t)
	fixture.writeBridge(t, nil)
	fixture.reopen(t)
	finalOld := fixture.read(t, fixture.dated, len(fixture.first), fixture.unread)
	if finalOld.FileID != initial.FileID {
		t.Fatalf("rotated bytes changed file ID")
	}
	fixture.reopen(t)
	fixture.read(t, fixture.protected, 0, fixture.after)
	fixture.reopen(t)
	fixture.read(t, fixture.path+".1", 0, fixture.numbered)
	fixture.read(t, fixture.path, 0, fixture.current)
}

func TestDeviceSignalDatedRotationRejectsUnverifiedSuccessors(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, deviceSignalRotationBridgeFixture)
	}{
		{"missing bridge", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			if err := os.Remove(f.bridge); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong source", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			f.writeBridge(t, func(data map[string]any) { data["source_path"] = f.path + ".unrelated" })
		}},
		{"wrong epoch", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			f.writeBridge(t, func(data map[string]any) { data["epoch"] = "different" })
		}},
		{"oversized bridge", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			raw, err := os.ReadFile(f.bridge)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.bridge, append(raw, bytes.Repeat([]byte{' '}, 16<<10)...), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"old content conflict", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			f.writeBridge(t, func(data map[string]any) {
				data["from"].(map[string]any)["sha256"] = data["to"].(map[string]any)["sha256"]
			})
		}},
		{"unavailable successor", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			if err := os.Remove(f.protected); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed successor", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			writeGzipFixture(t, f.protected, f.numbered)
		}},
		{"corrupt gzip with corresponding checksum", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			raw, err := os.ReadFile(f.protected)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-8] ^= 0x80
			if err := os.WriteFile(f.protected, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			f.writeBridge(t, nil)
		}},
		{"truncated old file", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			if err := os.Truncate(f.dated, int64(len(f.first))); err != nil {
				t.Fatal(err)
			}
		}},
		{"unfinished old record with corresponding checksum", func(t *testing.T, f deviceSignalRotationBridgeFixture) {
			raw, err := os.ReadFile(f.dated)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.dated, append(raw, []byte("{\"partial\":")...), 0o600); err != nil {
				t.Fatal(err)
			}
			f.writeBridge(t, nil)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := setupDeviceSignalRotationBridge(t)
			f.rotate(t)
			f.writeBridge(t, nil)
			before := f.read(t, f.dated, 0, append(bytes.Clone(f.first), f.unread...))
			test.mutate(t, f)
			f.reopen(t)
			_, captured, err := CaptureStreamOnce(context.Background(), f.journal, Options{SensorID: "sensor-a"}, f.source)
			if !errors.Is(err, ErrStreamSourceGap) || captured {
				t.Fatalf("unverified successor captured = %t, err = %v", captured, err)
			}
			after, err := f.journal.LoadSource(f.source.Kind, f.path)
			if err != nil || before != after {
				t.Fatalf("cursor moved on a gap: %+v to %+v: %v", before, after, err)
			}
		})
	}
}

type deviceSignalRotationBridgeFixture struct {
	path, dated, protected, bridge          string
	first, unread, after, numbered, current []byte
	source                                  Source
	journal                                 *streamlog.Journal
}

func setupDeviceSignalRotationBridge(t *testing.T) deviceSignalRotationBridgeFixture {
	t.Helper()
	t.Setenv("PROXY_SENTINEL_STREAM_FILE_BIRTH_ID", "true")
	dir := t.TempDir()
	recovery := filepath.Join(dir, "protected")
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(deviceSignalRecoveryDirEnv, recovery)
	path := filepath.Join(dir, "ttl.jsonl")
	t.Cleanup(func() { clearSignalGzip(path) })
	now := time.Now().UTC()
	scope := &normalized.CaptureScope{
		SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "packet-owner",
		CampusID: "campus-a", AccessDomain: "bond0", InterfaceName: "bond0",
		ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour),
	}
	line := func(id string) []byte {
		event := scope.Apply(normalized.Event{
			SchemaVersion: "v1", EventID: id, Source: "packet-sidecar", SourceEventType: "ssdp",
			Type: "device", Timestamp: now.Format(time.RFC3339Nano),
			Observer: map[string]any{"sensor_id": "sensor-a", "collector_instance_id": "packet-owner", "interface": "bond0"},
			Subject:  map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"origin": "ssdp"},
		})
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	j, err := streamlog.Open(filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	f := deviceSignalRotationBridgeFixture{
		path: path, dated: path + "-20261125-034302",
		protected: filepath.Join(recovery, "ttl-chain-000000000019.jsonl.gz"), bridge: filepath.Join(recovery, "ttl-rotation-bridge.json"),
		first: line("first"), unread: line("unread"), after: line("after"), numbered: line("numbered"), current: line("current"),
		source:  Source{Kind: "device-signals", Path: path, CaptureScope: scope, ControlledInterface: "bond0"},
		journal: j,
	}
	if err := os.WriteFile(path, append(bytes.Clone(f.first), f.unread...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{
		Epoch: "existing-epoch", Source: f.source.Kind, Path: path, FileID: FileIdentityBirth(path, mustStat(t, path)),
		ParserVersion: "device-v1",
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f deviceSignalRotationBridgeFixture) rotate(t *testing.T) {
	t.Helper()
	if err := os.Rename(f.path, f.dated); err != nil {
		t.Fatal(err)
	}
	writeGzipFixture(t, f.path+".2.gz", f.after)
	if err := os.Link(f.path+".2.gz", f.protected); err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{f.path + ".1": f.numbered, f.path: f.current} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f deviceSignalRotationBridgeFixture) writeBridge(t *testing.T, mutate func(map[string]any)) {
	t.Helper()
	file := func(path string) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return map[string]any{
			"name": filepath.Base(path), "file_id": FileIdentityBirthAt(f.path, path, mustStat(t, path)),
			"bytes": len(raw), "sha256": hex.EncodeToString(sum[:]),
		}
	}
	data := map[string]any{
		"schema_version": "device-signal-rotation-bridge/v1", "source_path": f.path,
		"epoch": "existing-epoch", "from": file(f.dated), "to": file(f.protected),
	}
	if mutate != nil {
		mutate(data)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.bridge, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *deviceSignalRotationBridgeFixture) reopen(t *testing.T) {
	t.Helper()
	clearSignalGzip(f.path)
	journal, err := streamlog.Open(f.journal.Directory())
	if err != nil {
		t.Fatal(err)
	}
	f.journal = journal
}

func (f deviceSignalRotationBridgeFixture) read(t *testing.T, expectedPath string, start int, raw []byte) streamlog.SourceCursor {
	t.Helper()
	id, captured, err := CaptureStreamOnce(context.Background(), f.journal,
		Options{SensorID: "sensor-a", MaxBatchBytes: int64(len(raw))}, f.source)
	if err != nil || !captured {
		t.Fatalf("capture %s at %d: captured=%t err=%v", filepath.Base(expectedPath), start, captured, err)
	}
	state, err := f.journal.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	expectedID := FileIdentityBirthAt(f.path, expectedPath, mustStat(t, expectedPath))
	if !bytes.Equal(state.Segment.Raw, raw) || len(state.Segment.Events) != bytes.Count(raw, []byte{'\n'}) ||
		state.Segment.FileID != expectedID || state.Segment.StartOffset != int64(start) ||
		state.Segment.EndOffset != int64(start+len(raw)) || state.Segment.Epoch != "existing-epoch" {
		t.Fatalf("wrong captured interval: file %s, offset %d to %d, epoch %s", state.Segment.FileID, state.Segment.StartOffset, state.Segment.EndOffset, state.Segment.Epoch)
	}
	cursor, err := f.journal.LoadSource(f.source.Kind, f.path)
	if err != nil || cursor.FileID != expectedID || cursor.Offset != state.Segment.EndOffset || cursor.Epoch != state.Segment.Epoch {
		t.Fatalf("wrong committed interval: %+v %v", cursor, err)
	}
	return cursor
}
