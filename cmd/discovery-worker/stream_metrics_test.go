package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

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
	m.queue("unknown", 999, 999)
	snapshot := m.snapshot("periodic", time.Now())
	stats := snapshot.Stages["archive.write"]
	if stats.Count != 401 || stats.Failures != 1 || stats.TotalMS != 803 || stats.MaxMS != 3 {
		t.Fatalf("unexpected bounded summary: %+v", stats)
	}
	if len(snapshot.Stages) != 1 || len(snapshot.Queues) != 1 || snapshot.Queues["archive"].Depth != 3 || snapshot.Queues["archive"].SampledMax != 64 {
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
