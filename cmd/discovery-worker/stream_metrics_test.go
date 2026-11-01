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
