package realtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestDeviceSignalStream4SwitchAppliesOnlyToFutureProjectionEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packet.jsonl")
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
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fixed-epoch", Source: "device-signals", Path: path, FileID: fileIdentity(path, info), ParserVersion: "device-v1"}); err != nil {
		t.Fatal(err)
	}
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "signal-owner", CampusID: "campus-a", AccessDomain: "bond0", InterfaceName: "bond0", ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}
	encode := func(id, eventType string) []byte {
		event := normalized.Event{SchemaVersion: "v1", EventID: id, Source: "device-signals", SourceEventType: eventType, Type: "device", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor-a", "collector_instance_id": "signal-owner", "interface": "bond0"}, Subject: map[string]any{"ip": "192.0.2.8"}, Payload: map[string]any{"origin": eventType}}
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(scope.Apply(event)); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	first := encode("old", "ndp")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	source := Source{Kind: "device-signals", Path: path, CaptureScope: scope, ControlledInterface: "bond0"}
	oldID, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a"}, source)
	if err != nil || !captured {
		t.Fatalf("legacy capture: %s %v", oldID, err)
	}
	old, err := j.Load(oldID)
	if err != nil || len(old.Segment.Events) != 1 || !strings.HasPrefix(old.Segment.Events[0].EventID, "stream-") {
		t.Fatalf("legacy key changed: %+v %v", old.Segment.Events, err)
	}
	additional := append(append(append([]byte(nil), encode("only-archive", "ttl")...), encode("project-0", "ndp")...), encode("project-1", "ssdp")...)
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		t.Fatal(err)
	} else if _, err := f.Write(additional); err != nil {
		f.Close()
		t.Fatal(err)
	} else if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	id, captured, err := CaptureStreamOnce(context.Background(), j, Options{SensorID: "sensor-a", DeviceSignalStream4Keys: true}, source)
	if err != nil || !captured {
		t.Fatalf("stream4 capture: %s %v", id, err)
	}
	state, err := j.Load(id)
	if err != nil || len(state.Segment.Events) != 3 {
		t.Fatalf("mixed segment: %+v %v", state.Segment.Events, err)
	}
	if !strings.HasPrefix(state.Segment.Events[0].EventID, "stream-") || state.Segment.Events[1].EventID != "stream4-"+id+"-0" || state.Segment.Events[2].EventID != "stream4-"+id+"-1" {
		t.Fatalf("mixed event keys: %s %s %s", state.Segment.Events[0].EventID, state.Segment.Events[1].EventID, state.Segment.Events[2].EventID)
	}
	if state.Segment.Events[1].RawRef["producer_event_id"] != "project-0" || state.Segment.Events[2].RawRef["producer_event_id"] != "project-1" {
		t.Fatal("producer source identities lost")
	}
	legacy, err := j.Load(oldID)
	if err != nil || legacy.Segment.Events[0].EventID != old.Segment.Events[0].EventID {
		t.Fatal("writer switch modified durable legacy segment")
	}
}
