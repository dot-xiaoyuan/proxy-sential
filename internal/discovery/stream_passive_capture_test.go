package discovery

import (
	"context"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestAppendPassiveStreamBatchFixesScopeAndSourcePosition(t *testing.T) {
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := PassiveStreamSourcePath(source)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", Offset: 0, ParserVersion: "passive-frame-v1"}); err != nil {
		t.Fatal(err)
	}
	event := streamDiscoveryEvent("producer-id", at.Format(time.RFC3339Nano), 600)
	event.Observer["capture_scope_id"] = ""
	event.Observer["interface"] = "bond0"
	event.Subject["site"] = "site-a"
	event.Subject["domain"] = "domain-a"
	id, err := AppendPassiveStreamBatch(context.Background(), j, source, scope, []normalized.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil {
		t.Fatal(err)
	}
	got := state.Segment.Events[0]
	if got.EventID == "producer-id" || got.Observer["capture_scope_id"] == "" || got.RawRef["producer_event_id"] != "producer-id" {
		t.Fatalf("source event lacks fixed new identity: %+v", got)
	}
	if state.Segment.RawSHA256 != "" || len(state.Segment.Raw) != 0 || state.Segment.StartOffset != 0 || state.Segment.EndOffset <= 0 {
		t.Fatalf("virtual position or duplicate packet body wrong: %+v", state.Segment)
	}
	cursor, err := j.LoadSource("passive-discovery", path)
	if err != nil || cursor.Offset != state.Segment.EndOffset {
		t.Fatalf("source cursor was not committed: %+v %v", cursor, err)
	}
}

func TestAppendPassiveStreamBatchRejectsScopeConflictWithoutAdvancing(t *testing.T) {
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "other-site", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := PassiveStreamSourcePath(source)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", Offset: 0, ParserVersion: "passive-frame-v1"}); err != nil {
		t.Fatal(err)
	}
	_, captureErr := AppendPassiveStreamBatch(context.Background(), j, source, scope, []normalized.Event{streamDiscoveryEvent("producer-id", at.Format(time.RFC3339Nano), 600)})
	if captureErr == nil {
		t.Fatal("site conflict accepted")
	}
	cursor, err := j.LoadSource("passive-discovery", path)
	if err != nil || cursor.Offset != 0 {
		t.Fatalf("scope conflict advanced source: %+v %v", cursor, err)
	}
}
