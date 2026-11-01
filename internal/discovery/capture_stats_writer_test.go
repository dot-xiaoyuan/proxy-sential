package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaptureShutdownKeepsRealFailuresWhenWritersAreCancelled(t *testing.T) {
	diskErr := errors.New("statistics disk failed")
	overflow := errors.New("passive spool queue full")
	cancelled := fmt.Errorf("capture stopped: %w", context.Canceled)
	for _, errs := range [][]error{
		{context.Canceled, diskErr},
		{overflow, cancelled},
		{overflow, diskErr, cancelled},
		{errors.Join(overflow, context.Canceled), diskErr},
	} {
		got := joinCaptureErrors(errs...)
		if got == nil || got == context.Canceled {
			t.Fatalf("real shutdown error hidden: %v", errs)
		}
		for _, err := range errs {
			if errors.Is(err, diskErr) && !errors.Is(got, diskErr) || errors.Is(err, overflow) && !errors.Is(got, overflow) {
				t.Fatalf("failure removed: %v -> %v", errs, got)
			}
		}
	}
	if got := joinCaptureErrors(nil, cancelled, context.Canceled); got != context.Canceled {
		t.Fatalf("clean cancellation was not normalized: %v", got)
	}
	if got := joinCaptureErrors(nil, nil); got != nil {
		t.Fatalf("successful shutdown failed: %v", got)
	}
}

func TestCaptureStatsWriterSlowDiskKeepsOnlyLatestSnapshot(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var persisted []*CaptureStats
	writer := newCaptureStatsWriter(func(snapshot *CaptureStats) error {
		if len(persisted) == 0 {
			close(started)
			<-release
		}
		persisted = append(persisted, snapshot)
		return nil
	})
	stats := NewCaptureStats()
	stats.Config = DefaultCollectionConfig()
	stats.record("arp", 1)
	if err := writer.submit(stats); err != nil {
		t.Fatal(err)
	}
	<-started
	// A blocked filesystem must neither hold up capture nor accumulate a
	// goroutine or snapshot per heartbeat. All counters are cumulative.
	for range 10000 {
		stats.record("arp", 1)
		if err := writer.submit(stats); err != nil {
			t.Fatal(err)
		}
	}
	stats.Config.Protocols[0].Enabled = false
	stats.Protocols["arp"].Received = 99999
	close(release)
	if err := writer.close(); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 2 || persisted[0].Protocols["arp"].Received != 1 || persisted[1].Protocols["arp"].Received != 10001 {
		t.Fatalf("wrong retained snapshots: %#v", persisted)
	}
	if !persisted[1].Config.Protocols[0].Enabled {
		t.Fatal("published configuration was mutated by capture")
	}
	if persisted[0].UpdatedAt.IsZero() || persisted[1].UpdatedAt.Before(persisted[0].UpdatedAt) {
		t.Fatal("snapshot observation time missing")
	}
}

func TestCaptureStatsWriterErrorIsVisibleToCaptureAndClose(t *testing.T) {
	failure := errors.New("stats disk failed")
	writer := newCaptureStatsWriter(func(*CaptureStats) error { return failure })
	if err := writer.submit(NewCaptureStats()); err != nil {
		t.Fatal(err)
	}
	<-writer.done
	if !errors.Is(writer.err(), failure) || !errors.Is(writer.submit(NewCaptureStats()), failure) || !errors.Is(writer.close(), failure) {
		t.Fatal("statistics I/O failure was hidden")
	}
}

func TestCaptureStatsWriterCloseFlushesFinalOverflowSnapshot(t *testing.T) {
	dir := t.TempDir()
	writer := newCaptureStatsWriter(func(snapshot *CaptureStats) error { return snapshot.persistSnapshot(dir) })
	stats := NewCaptureStats()
	stats.recordQueue(256, 256, true)
	if err := writer.submit(stats); err != nil {
		t.Fatal(err)
	}
	if err := writer.close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "capture.stats"))
	if err != nil {
		t.Fatal(err)
	}
	var got CaptureStats
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Queue.Batches != 256 || got.Queue.Capacity != 256 || got.Queue.PeakObservedBatches != 256 || got.Queue.FullCount != 1 {
		t.Fatalf("overflow evidence lost: %+v", got.Queue)
	}
	stats.recordQueue(0, 256, false)
	if stats.Queue.PeakObservedBatches != 256 || stats.Queue.FullCount != 1 {
		t.Fatal("draining erased queue history")
	}
}

func TestCaptureStatsSnapshotPersistenceKeepsObservationTime(t *testing.T) {
	stats := NewCaptureStats()
	stats.UpdatedAt = time.Date(2026, 11, 1, 1, 2, 3, 0, time.UTC)
	dir := t.TempDir()
	if err := stats.persistSnapshot(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "capture.stats"))
	if err != nil {
		t.Fatal(err)
	}
	var got CaptureStats
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.UpdatedAt.Equal(stats.UpdatedAt) {
		t.Fatal("slow persistence made an old heartbeat look fresh")
	}
}
