package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestProjectionWriteMetricsKeepSourceEpochWindows(t *testing.T) {
	metrics := newPassiveStreamMetrics()
	confirmed := streamlog.Segment{Source: "passive-discovery", Epoch: "fresh-a", Events: make([]normalized.Event, 100)}
	metrics.observeCapture(streamlog.Segment{Source: "passive-discovery", Epoch: "fresh-a", StartOffset: 10, EndOffset: 5010, Events: make([]normalized.Event, 100)})
	metrics.observeCapture(streamlog.Segment{Source: "passive-discovery", Epoch: "fresh-a", StartOffset: 5010, EndOffset: 9010, Events: make([]normalized.Event, 80)})
	metrics.observeCapture(streamlog.Segment{Source: "passive-discovery", Epoch: "fresh-b", StartOffset: 0, EndOffset: 500, Events: make([]normalized.Event, 10)})
	metrics.observeCapture(streamlog.Segment{Source: "passive-discovery", Epoch: "fresh-b", StartOffset: 500, EndOffset: 0, Events: make([]normalized.Event, 999)})
	metrics.observeAck(streamlog.Archive, confirmed)
	metrics.observeAck(streamlog.Search, confirmed)
	metrics.observeAck(streamlog.EventBus, confirmed)
	metrics.observeProjectionWrite(discovery.StreamProjectionWriteStats{Source: "passive-discovery", Epoch: "fresh-a", Events: 100, FactRows: 7, StateRows: 2})
	metrics.observeProjectionWrite(discovery.StreamProjectionWriteStats{Source: "passive-discovery", Epoch: "fresh-a", Events: 80, FactRows: 4, StateRows: 1})
	metrics.observeProjectionWrite(discovery.StreamProjectionWriteStats{Source: "passive-discovery", Epoch: "fresh-b", Events: 10, FactRows: 1, StateRows: 1})
	snapshot := metrics.snapshot("test", time.Now())
	first := snapshot.ProjectionWrites["passive-discovery/fresh-a"]
	if first.Segments != 2 || first.Events != 180 || first.FactRows != 11 || first.StateRows != 3 {
		t.Fatalf("wrong committed projection writes: %+v", first)
	}
	if second := snapshot.ProjectionWrites["passive-discovery/fresh-b"]; second.Events != 10 || second.StateRows != 1 {
		t.Fatalf("epochs were mixed: %+v", snapshot.ProjectionWrites)
	}
	acks := snapshot.SinkAcks["passive-discovery/fresh-a"]
	if acks.BodyEvents != 100 || acks.SearchEvents != 100 || acks.BusEvents != 100 || acks.BodySegments != 1 || acks.SearchSegments != 1 || acks.BusSegments != 1 {
		t.Fatalf("wrong journal-confirmed sink writes: %+v", acks)
	}
	if got := snapshot.CaptureAccepted["passive-discovery/fresh-a"]; got.Segments != 2 || got.Events != 180 || got.SourceBytes != 9000 {
		t.Fatalf("wrong source/epoch capture count: %+v", got)
	}
	if got := snapshot.CaptureAccepted["passive-discovery/fresh-b"]; got.Segments != 1 || got.Events != 10 || got.SourceBytes != 500 {
		t.Fatalf("capture epochs mixed or invalid offset counted: %+v", got)
	}
	if got := metrics.snapshot("test", time.Now()); len(got.ProjectionWrites) != 0 {
		t.Fatalf("projection window did not reset: %+v", got.ProjectionWrites)
	}
	if got := metrics.snapshot("test", time.Now()); len(got.SinkAcks) != 0 {
		t.Fatalf("sink ack window did not reset: %+v", got.SinkAcks)
	}
	if got := metrics.snapshot("test", time.Now()); len(got.CaptureAccepted) != 0 {
		t.Fatalf("capture window did not reset: %+v", got.CaptureAccepted)
	}
}

func TestPassiveStreamMetricsBoundedAndReset(t *testing.T) {
	m := newPassiveStreamMetrics()
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				m.observe(streamlog.Archive, streamlog.StageWrite, 2*time.Millisecond, nil)
			}
		}()
	}
	workers.Wait()
	m.observe(streamlog.Archive, streamlog.StageWrite, 3*time.Millisecond, errors.New("secret evidence"))
	m.observe("segment-private", streamlog.StageWrite, time.Second, nil)
	m.observe(streamlog.Archive, "custom-private", time.Second, nil)
	m.queue("archive", 64, 64)
	m.queue("archive", 3, 64)
	m.queue("eventbus", 2, 64)
	m.queue("unknown", 999, 999)
	snapshot := m.snapshot("periodic", time.Now())
	stats := snapshot.Stages["archive.write"]
	if stats.Count != 401 || stats.Failures != 1 || stats.TotalMS != 803 || stats.MaxMS != 3 {
		t.Fatalf("unexpected bounded summary: %+v", stats)
	}
	if len(snapshot.Stages) != 1 || len(snapshot.Queues) != 2 || snapshot.Queues["archive"].Depth != 3 || snapshot.Queues["archive"].SampledMax != 64 || snapshot.Queues["eventbus"].Depth != 2 {
		t.Fatalf("unexpected dimensions: %+v", snapshot)
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "private") || strings.Contains(string(b), "secret") {
		t.Fatal("metrics leaked unbounded labels or errors")
	}
	reset := m.snapshot("shutdown", time.Now())
	if len(reset.Stages) != 0 || reset.Queues["archive"].SampledMax != 3 {
		t.Fatalf("metrics window not reset: %+v", reset)
	}
}

func TestPassiveStreamEnqueueCancellationIsVisible(t *testing.T) {
	m := newPassiveStreamMetrics()
	queue := make(chan string, 1)
	queue <- "first"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := enqueuePassiveLane(ctx, queue, "second", streamlog.Archive, m); !errors.Is(err, context.Canceled) {
		t.Fatalf("enqueue: %v", err)
	}
	snapshot := m.snapshot("shutdown", time.Now())
	stats := snapshot.Stages["archive.enqueue"]
	if stats.Count != 1 || stats.Failures != 1 || snapshot.Queues["archive"].Depth != 1 {
		t.Fatalf("blocked enqueue lost: %+v", snapshot)
	}
	if <-queue != "first" {
		t.Fatal("cancelled enqueue changed queue")
	}
}

func TestPassiveJournalPhasesAndBatchSizesStayBounded(t *testing.T) {
	m := newPassiveStreamMetrics()
	m.observeJournal(streamlog.PassiveJournalPhases{
		AppendAttempted: true, CommitAttempted: true,
		AppendDuration: 150 * time.Millisecond, CommitDuration: 300 * time.Millisecond,
		CommitAckDuration: 80 * time.Millisecond,
	}, 625, 600<<10, errors.New("sensitive segment content"))
	snapshot := m.snapshot("periodic", time.Now())
	if appendStage := snapshot.Stages["capture.append"]; appendStage.Count != 1 || appendStage.Failures != 0 || appendStage.TotalMS != 150 {
		t.Fatalf("append phase: %+v", appendStage)
	}
	if commitStage := snapshot.Stages["capture.commit"]; commitStage.Count != 1 || commitStage.Failures != 1 || commitStage.TotalMS != 300 {
		t.Fatalf("commit phase: %+v", commitStage)
	}
	if ackStage := snapshot.Stages["capture.commit.ack"]; ackStage.Count != 1 || ackStage.TotalMS != 80 {
		t.Fatalf("commit ACK phase: %+v", ackStage)
	}
	if batches := snapshot.CaptureBatches; batches.Count != 1 || batches.Events != 625 || batches.SourceBytes != 600<<10 || batches.EventsLE750 != 1 || batches.BytesLE1MiB != 1 {
		t.Fatalf("capture batch sizes: %+v", batches)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(encoded), "sensitive") {
		t.Fatalf("bounded snapshot leaked error: %s %v", encoded, err)
	}
	reset := m.snapshot("shutdown", time.Now())
	if reset.CaptureBatches.Count != 0 || len(reset.Stages) != 0 {
		t.Fatalf("capture dimensions did not reset: %+v", reset)
	}
}
