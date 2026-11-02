//go:build linux

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestStreamCaptureQueueDrainsToJournalAfterCancellation(t *testing.T) {
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := Source{ID: "passive-sensor-a", Node: "sensor-a", Site: "site-a", Domain: "domain-a", Address: "bond0"}
	path := PassiveStreamSourcePath(source)
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: "fresh-1", Source: "passive-discovery", Path: path, FileID: "boot-a", ParserVersion: PassiveStreamParserVersion}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: source.Node, CollectorInstanceID: "boot-a", CampusID: source.Site, AccessDomain: source.Domain, InterfaceName: source.Address, ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan []byte, 2)
	for _, id := range []string{"first", "second"} {
		event := streamDiscoveryEvent(id, at.Format(time.RFC3339Nano), 600)
		event.Observer["interface"] = source.Address
		raw, err := json.Marshal([]normalized.Event{event})
		if err != nil {
			t.Fatal(err)
		}
		queue <- raw
	}
	close(queue)
	callbacks := 0
	persist := func(raw []byte) error {
		return persistPassiveStreamCaptureBatch(ctx, j, source, scope, false, func(CapturedSegment) error {
			callbacks++
			cancel() // A lane enqueue can observe cancellation after the append.
			return ctx.Err()
		}, raw)
	}
	if err := drainSpoolQueueBoundedWindow(queue, persist, 1, 1<<20, 0); err != nil {
		t.Fatal(err)
	}
	if callbacks != 1 {
		t.Fatalf("callback count = %d, want one before cancellation", callbacks)
	}
	recovered, err := j.RecoverSource("passive-discovery", path)
	if err != nil || len(recovered) != 2 {
		t.Fatalf("queued segments were not recoverable: ids=%v err=%v", recovered, err)
	}
	for i, id := range recovered {
		state, err := j.Load(id)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"first", "second"}[i]
		if len(state.Segment.Events) != 1 || state.Segment.Events[0].RawRef["producer_event_id"] != want {
			t.Fatalf("recovered segment %d lost queued event %q: %+v", i, want, state.Segment.Events)
		}
	}
}

func TestPassiveStreamCaptureBudgetOptIn(t *testing.T) {
	for _, sample := range []struct {
		configured, events, bytes int
		invalid                   bool
	}{{0, 1000, 1 << 20, false}, {2000, 2000, 2 << 20, false}, {1999, 0, 0, true}} {
		gotEvents, gotBytes, err := passiveStreamCaptureBudget(CollectionConfig{PassiveSegmentMaxEvents: sample.configured})
		if gotEvents != sample.events || gotBytes != sample.bytes || (err != nil) != sample.invalid {
			t.Fatalf("configured=%d budget=%d/%d err=%v", sample.configured, gotEvents, gotBytes, err)
		}
	}
}

func TestCanceledCaptureWaitsForFinalQueueSlotOrWriterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	queue := make(chan []byte, 1)
	queue <- []byte("older")
	done := make(chan error, 1)
	first := make(chan []byte, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		first <- <-queue
	}()
	if err := enqueueCaptureBatch(ctx, queue, done, []byte("final"), NewCaptureStats(), true); err != nil {
		t.Fatal(err)
	}
	if string(<-first) != "older" || string(<-queue) != "final" {
		t.Fatal("final batch was not queued after cancellation")
	}
	queue <- []byte("older")
	failure := errors.New("journal writer failed")
	done <- failure
	if err := enqueueCaptureBatch(ctx, queue, done, []byte("final"), NewCaptureStats(), true); !errors.Is(err, failure) {
		t.Fatalf("writer failure was not reported: %v", err)
	}
}
