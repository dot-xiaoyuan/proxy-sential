package discovery

import (
	"context"
	"encoding/json"
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

func TestPassiveStream3ProducerReplaysSourceBoundKeysAfterJournalRestart(t *testing.T) {
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(24 * time.Hour)}
	path := PassiveStreamSourcePath(source)
	dir := t.TempDir()
	j, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	events := []normalized.Event{
		streamDiscoveryEvent("producer-a", at.Format(time.RFC3339Nano), 600),
		streamDiscoveryEvent("producer-b", at.Add(time.Second).Format(time.RFC3339Nano), 600),
	}
	for i := range events {
		events[i].Observer["interface"] = "bond0"
		events[i].Subject["site"], events[i].Subject["domain"] = "site-a", "domain-a"
	}
	captured, err := appendPassiveStreamBatchWithScheme(context.Background(), j, source, scope, events, passiveEventKeyStream3)
	if err != nil {
		t.Fatal(err)
	}
	if captured.ID != streamlog.SourceSegmentID(captured.Segment) || captured.Segment.EndOffset <= captured.Segment.StartOffset {
		t.Fatalf("stream3 key source interval changed: %+v", captured)
	}
	for ordinal, event := range captured.Segment.Events {
		want := fmt.Sprintf("stream3-%s-%d", captured.ID, ordinal)
		if event.EventID != want || event.RawRef["producer_event_id"] != events[ordinal].EventID || event.RawRef["source_record_ordinal"] != ordinal {
			t.Fatalf("stream3 source position or producer evidence lost: %+v", event)
		}
	}
	reopened, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := reopened.RecoverSource("passive-discovery", path)
	if err != nil || len(ids) != 1 || ids[0] != captured.ID {
		t.Fatalf("stream3 restart lost durable segment: ids=%v err=%v", ids, err)
	}
	state, err := reopened.Load(captured.ID)
	if err != nil || state.Segment.Events[1].EventID != fmt.Sprintf("stream3-%s-1", captured.ID) {
		t.Fatalf("stream3 restart changed event identity: %+v err=%v", state, err)
	}
	prepared, err := prepareStreamDiscovery(state.Segment)
	if err != nil || verifyStream3PreparedSegment(captured.ID, state.Segment, prepared) != nil {
		t.Fatalf("stream3 restart lost projectable proof: %v", err)
	}
	var ref map[string]string
	if err := json.Unmarshal(streamDiscoveryBodyRef(state.Segment, prepared[0].Receipt), &ref); err != nil ||
		ref["key"] != "fresh-1:"+state.Segment.Events[0].EventID || ref["sha256"] != prepared[0].Receipt.Hash ||
		ref["scope"] != prepared[0].Receipt.Scope || ref["month"] != state.Segment.ArchiveMonth {
		t.Fatalf("stream3 original body locator changed: %+v err=%v", ref, err)
	}
}

func TestPassiveStream3InterruptedSourceCommitReusesDurableKeys(t *testing.T) {
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := PassiveStreamSourcePath(source)
	cursor := streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}
	event := streamDiscoveryEvent("producer-id", at.Format(time.RFC3339Nano), 600)
	event.Observer["interface"] = "bond0"
	event.Subject["site"], event.Subject["domain"] = "site-a", "domain-a"
	interrupted := &passiveAtomicTestJournal{cursor: cursor, err: errors.New("source commit interrupted")}
	captured, err := appendPassiveStreamBatchWithScheme(context.Background(), interrupted, source, scope,
		[]normalized.Event{event}, passiveEventKeyStream3)
	if err == nil || captured.Segment.Events[0].EventID != fmt.Sprintf("stream3-%s-0", streamlog.SourceSegmentID(captured.Segment)) {
		t.Fatalf("interrupted append lost source-bound key: %+v err=%v", captured, err)
	}
	dir := t.TempDir()
	j, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(cursor); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(captured.Segment) // Durable body exists, but source commit has not occurred.
	if err != nil || id != streamlog.SourceSegmentID(captured.Segment) {
		t.Fatalf("interrupted body identity: id=%s err=%v", id, err)
	}
	reopened, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := reopened.RecoverSource("passive-discovery", path)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("interrupted body not recovered: ids=%v err=%v", ids, err)
	}
	replayed, err := reopened.Load(id)
	if err != nil || replayed.Segment.Events[0].EventID != captured.Segment.Events[0].EventID {
		t.Fatalf("interrupted replay changed key: %+v err=%v", replayed, err)
	}
	if again, err := reopened.AppendAndCommitPassive(captured.Segment); err != nil || again != id {
		t.Fatalf("idempotent source replay changed identity: id=%s err=%v", again, err)
	}
	committed, err := reopened.LoadSource("passive-discovery", path)
	if err != nil || committed.Offset != captured.Segment.EndOffset {
		t.Fatalf("source replay did not commit original interval: %+v err=%v", committed, err)
	}
}

func TestPassiveStream3WALRestartRetainsSegmentIdentity(t *testing.T) {
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := PassiveStreamSourcePath(source)
	legacy, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	wal, err := streamlog.OpenPassiveWALJournal(legacy, path, streamlog.PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	event := streamDiscoveryEvent("producer-id", at.Format(time.RFC3339Nano), 600)
	event.Observer["interface"] = "bond0"
	event.Subject["site"], event.Subject["domain"] = "site-a", "domain-a"
	captured, err := appendPassiveStreamBatchWithScheme(context.Background(), wal, source, scope,
		[]normalized.Event{event}, passiveEventKeyStream3)
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := streamlog.OpenPassiveWALJournal(legacy, path, streamlog.PassiveWALOptions{WriteEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	state, err := reopened.Load(captured.ID)
	if err != nil || state.Segment.Events[0].EventID != fmt.Sprintf("stream3-%s-0", captured.ID) {
		t.Fatalf("WAL restart changed stream3 key: %+v err=%v", state, err)
	}
	cursor, err := reopened.LoadSource("passive-discovery", path)
	if err != nil || cursor.Offset != captured.Segment.EndOffset || cursor.LastSegmentID != captured.ID {
		t.Fatalf("WAL restart changed source cursor: %+v err=%v", cursor, err)
	}
}

func TestPassiveStream3CutoverKeepsOlderStream2Segment(t *testing.T) {
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	at := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "sensor-a", CollectorInstanceID: "boot-a", CampusID: "site-a", AccessDomain: "domain-a", InterfaceName: "bond0", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	path := PassiveStreamSourcePath(source)
	dir := t.TempDir()
	j, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	event := streamDiscoveryEvent("producer-id", at.Format(time.RFC3339Nano), 600)
	event.Observer["interface"] = "bond0"
	event.Subject["site"], event.Subject["domain"] = "site-a", "domain-a"
	old, err := appendPassiveStreamBatch(context.Background(), j, source, scope, []normalized.Event{event}, true)
	if err != nil {
		t.Fatal(err)
	}
	newSegment, err := appendPassiveStreamBatchWithScheme(context.Background(), j, source, scope,
		[]normalized.Event{event}, passiveEventKeyStream3)
	if err != nil {
		t.Fatal(err)
	}
	if newSegment.Segment.StartOffset != old.Segment.EndOffset ||
		!strings.HasPrefix(old.Segment.Events[0].EventID, "stream2-") ||
		newSegment.Segment.Events[0].EventID != fmt.Sprintf("stream3-%s-0", newSegment.ID) {
		t.Fatalf("stream3 cutover changed old source interval: old=%+v new=%+v", old.Segment, newSegment.Segment)
	}
	reopened, err := streamlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := reopened.RecoverSource("passive-discovery", path)
	if err != nil || len(ids) != 2 || ids[0] != old.ID || ids[1] != newSegment.ID {
		t.Fatalf("cutover replay lost an old or new segment: ids=%v err=%v", ids, err)
	}
	oldState, err := reopened.Load(old.ID)
	if err != nil || oldState.Segment.Events[0].EventID != old.Segment.Events[0].EventID {
		t.Fatalf("cutover replay rewrote stream2 identity: %+v err=%v", oldState, err)
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

func TestAppendPassiveStreamBatchTwoThousandEventBound(t *testing.T) {
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
	events := make([]normalized.Event, streamlog.MaxPassiveSegmentEvents+1)
	for i := range events {
		events[i] = streamDiscoveryEvent(fmt.Sprintf("producer-%d", i), at.Format(time.RFC3339Nano), 600)
		events[i].Observer["interface"] = "bond0"
		events[i].Subject["site"] = "site-a"
		events[i].Subject["domain"] = "domain-a"
	}
	id, err := AppendPassiveStreamBatch(context.Background(), j, source, scope, events[:streamlog.MaxPassiveSegmentEvents])
	if err != nil {
		t.Fatal(err)
	}
	state, err := j.Load(id)
	if err != nil || len(state.Segment.Events) != streamlog.MaxPassiveSegmentEvents ||
		state.Segment.Events[streamlog.MaxPassiveSegmentEvents-1].RawRef["source_record_ordinal"] != float64(streamlog.MaxPassiveSegmentEvents-1) {
		t.Fatalf("stored events=%d err=%v", len(state.Segment.Events), err)
	}
	if _, err := AppendPassiveStreamBatch(context.Background(), j, source, scope, events); err == nil {
		t.Fatal("oversized segment accepted")
	}
	cursor, err := j.LoadSource("passive-discovery", path)
	if err != nil || cursor.Offset != state.Segment.EndOffset {
		t.Fatalf("oversized segment changed cursor: %+v %v", cursor, err)
	}
	keyless, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := keyless.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	stream3, err := appendPassiveStreamBatchWithScheme(context.Background(), keyless, source, scope,
		events[:streamlog.MaxPassiveSegmentEvents], passiveEventKeyStream3)
	if err != nil {
		t.Fatal(err)
	}
	last := stream3.Segment.Events[streamlog.MaxPassiveSegmentEvents-1].EventID
	if last != fmt.Sprintf("stream3-%s-1999", stream3.ID) {
		t.Fatalf("last bounded stream3 ordinal changed: %s", last)
	}
	if _, err := appendPassiveStreamBatchWithScheme(context.Background(), keyless, source, scope,
		events, passiveEventKeyStream3); err == nil {
		t.Fatal("oversized stream3 segment accepted")
	}
	keylessCursor, err := keyless.LoadSource("passive-discovery", path)
	if err != nil || keylessCursor.Offset != stream3.Segment.EndOffset {
		t.Fatalf("oversized stream3 segment advanced cursor: %+v %v", keylessCursor, err)
	}
}
