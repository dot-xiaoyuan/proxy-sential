package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type passiveAtomicTestJournal struct {
	cursor  streamlog.SourceCursor
	segment streamlog.Segment
	calls   int
	err     error
}

func (j *passiveAtomicTestJournal) LoadSource(source, path string) (streamlog.SourceCursor, error) {
	if source != j.cursor.Source || path != j.cursor.Path {
		return streamlog.SourceCursor{}, streamlog.ErrContentConflict
	}
	return j.cursor, nil
}

func (j *passiveAtomicTestJournal) AppendAndCommitPassive(segment streamlog.Segment) (string, error) {
	j.calls++
	j.segment = segment
	if j.err == nil {
		time.Sleep(time.Microsecond)
	}
	return "durable-or-indeterminate-id", j.err
}

func TestAppendPassiveStreamBatchUsesAtomicPersistence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
			at := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
			scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-b", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
			j := &passiveAtomicTestJournal{cursor: streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: PassiveStreamSourcePath(source), FileID: "boot-a", Offset: 77, ParserVersion: PassiveStreamParserVersion}}
			if fail {
				j.err = errors.New("durability result is indeterminate")
			}
			event := streamDiscoveryEvent("producer-id", at.Format(time.RFC3339Nano), 600)
			event.Observer["interface"] = "bond0"
			event.Subject["site"], event.Subject["domain"] = "site-a", "domain-a"
			got, err := appendPassiveStreamBatch(context.Background(), j, source, scope, []normalized.Event{event}, false)
			if j.calls != 1 || j.segment.PreviousOffset != 77 || j.segment.PreviousFileID != "boot-a" || j.segment.StartOffset != 0 || j.segment.FileID != "boot-b" {
				t.Fatalf("atomic accept lost predecessor or collector boundary: calls=%d segment=%+v", j.calls, j.segment)
			}
			if got.ID != "durable-or-indeterminate-id" || got.Segment.AcceptedAt.IsZero() || !got.Segment.AcceptedAt.Equal(j.segment.AcceptedAt) {
				t.Fatalf("accept result lost recovery identity or original time: %+v", got)
			}
			if !errors.Is(err, j.err) || (fail && got.AppendCommitDuration != 0) || (!fail && got.AppendCommitDuration <= 0) {
				t.Fatalf("failed acceptance must not enter successful metrics: %v %+v", err, got)
			}
		})
	}
}

func TestPassiveCompactEventKeyHasDisjointStableNamespace(t *testing.T) {
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(24 * time.Hour)}
	path := PassiveStreamSourcePath(source)
	j := &passiveAtomicTestJournal{cursor: streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", Offset: 77, ParserVersion: PassiveStreamParserVersion}}
	event := streamDiscoveryEvent("producer-id", at.Format(time.RFC3339Nano), 600)
	event.Observer["interface"] = "bond0"
	event.Subject["site"], event.Subject["domain"] = "site-a", "domain-a"
	old, err := appendPassiveStreamBatch(context.Background(), j, source, scope, []normalized.Event{event}, false)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := appendPassiveStreamBatch(context.Background(), j, source, scope, []normalized.Event{event}, true)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := old.Segment.Events[0].EventID
	newKey := compact.Segment.Events[0].EventID
	if !strings.HasPrefix(oldKey, "stream-") || !strings.HasPrefix(newKey, "stream2-") || oldKey == newKey || strings.TrimPrefix(oldKey, "stream-") != strings.TrimPrefix(newKey, "stream2-") {
		t.Fatalf("source-position identity changed instead of namespace: old=%q compact=%q", oldKey, newKey)
	}
	if old.Segment.Events[0].RawRef["producer_event_id"] != "producer-id" || compact.Segment.Events[0].RawRef["producer_event_id"] != "producer-id" {
		t.Fatal("producer evidence was lost at key cutover")
	}
}

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
	captured, err := appendPassiveStreamBatch(context.Background(), j, source, scope, []normalized.Event{event}, false)
	if err != nil {
		t.Fatal(err)
	}
	if captured.AppendCommitDuration <= 0 {
		t.Fatal("successful append and commit duration missing")
	}
	state, err := j.Load(captured.ID)
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

func TestAppendPassiveStreamBatchThousandEventBound(t *testing.T) {
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := PassiveStreamSourcePath(source)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	events := make([]normalized.Event, streamlog.MaxSegmentEvents+1)
	for i := range events {
		events[i] = streamDiscoveryEvent(fmt.Sprintf("producer-%d", i), at.Format(time.RFC3339Nano), 600)
		events[i].Observer["interface"] = "bond0"
		events[i].Subject["site"] = "site-a"
		events[i].Subject["domain"] = "domain-a"
	}
	id, err := AppendPassiveStreamBatch(context.Background(), j, source, scope, events[:streamlog.MaxSegmentEvents])
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || len(state.Segment.Events) != 1000 {
		t.Fatalf("stored events=%d err=%v", len(state.Segment.Events), err)
	}
	if _, err := AppendPassiveStreamBatch(context.Background(), j, source, scope, events); err == nil {
		t.Fatal("oversized segment accepted")
	}
	cursor, err := j.LoadSource("passive-discovery", path)
	if err != nil || cursor.Offset != state.Segment.EndOffset {
		t.Fatalf("oversized segment changed cursor: %+v %v", cursor, err)
	}
}
