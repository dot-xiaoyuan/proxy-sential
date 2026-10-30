package eventbus

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

type fakeProducer struct {
	mu      sync.Mutex
	records []Record
	fail    bool
	block   chan struct{}
	closed  bool
}

func (f *fakeProducer) Produce(ctx context.Context, record Record, done func(error)) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			if done != nil {
				done(ctx.Err())
			}
			return ctx.Err()
		}
	}
	if f.fail {
		err := errors.New("forced delivery failure")
		if done != nil {
			done(err)
		}
		return nil
	}
	f.mu.Lock()
	f.records = append(f.records, record)
	f.mu.Unlock()
	if done != nil {
		done(nil)
	}
	return nil
}

func (f *fakeProducer) Flush(context.Context) error { return nil }
func (f *fakeProducer) Close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

func (f *fakeProducer) snapshot() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.records...)
}

func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func testShadowConfig(t *testing.T, queue int) Config {
	t.Helper()
	return Config{
		Enabled:        true,
		DiscoveryTopic: "ps.test.discovery",
		Queue:          queue,
		MaxRecordBytes: 900 << 10,
		StatsPath:      filepath.Join(t.TempDir(), "eventbus.stats"),
		ClientID:       "test",
	}
}

func TestShadowPublishesSegmentEvents(t *testing.T) {
	cfg := testShadowConfig(t, 16)
	producer := &fakeProducer{}
	shadow := NewShadow(cfg, producer, func(event normalized.Event) (string, string) {
		return "key-" + event.EventID, "test"
	})
	at := time.Date(2026, 10, 30, 2, 15, 0, 0, time.UTC)
	shadow.Publish("segment-a", testSegment(at, testEvent("event-a", at), testEvent("event-b", at)))
	waitFor(t, "two published events", func() bool { return shadow.stats.Snapshot().Published == 2 })
	if err := shadow.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	records := producer.snapshot()
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	if string(records[0].Key) != "key-event-a" || string(records[1].Key) != "key-event-b" {
		t.Fatalf("keys = %q %q", records[0].Key, records[1].Key)
	}
	if _, err := os.Stat(cfg.StatsPath); err != nil {
		t.Fatalf("stats file: %v", err)
	}
	snapshot := shadow.stats.Snapshot()
	if snapshot.Segments != 1 || snapshot.Failed != 0 || snapshot.Dropped != 0 {
		t.Fatalf("stats = %+v", snapshot)
	}
}

func TestShadowCountsDeliveryFailureAndDoesNotBlockPublish(t *testing.T) {
	cfg := testShadowConfig(t, 16)
	producer := &fakeProducer{fail: true}
	shadow := NewShadow(cfg, producer, func(event normalized.Event) (string, string) {
		return "key-" + event.EventID, "test"
	})
	at := time.Now().UTC()
	shadow.Publish("segment-a", testSegment(at, testEvent("event-a", at)))
	waitFor(t, "one failed event", func() bool { return shadow.stats.Snapshot().Failed == 1 })
	if err := shadow.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(producer.snapshot()) != 0 {
		t.Fatal("failed records must not be counted as published")
	}
}

func TestShadowDropsWhenQueueIsFull(t *testing.T) {
	cfg := testShadowConfig(t, 1)
	block := make(chan struct{})
	producer := &fakeProducer{block: block}
	shadow := NewShadow(cfg, producer, func(event normalized.Event) (string, string) {
		return "key-" + event.EventID, "test"
	})
	at := time.Now().UTC()
	events := make([]normalized.Event, 0, 10)
	for i := 0; i < 10; i++ {
		events = append(events, testEvent(string(rune('a'+i)), at))
	}
	shadow.Publish("segment-a", testSegment(at, events...))
	waitFor(t, "dropped events", func() bool { return shadow.stats.Snapshot().Dropped >= 5 })
	close(block)
	if err := shadow.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := shadow.stats.Snapshot()
	if snapshot.Published+snapshot.Dropped != 10 {
		t.Fatalf("published+dropped = %d, stats=%+v", snapshot.Published+snapshot.Dropped, snapshot)
	}
}

func TestNilShadowIsSafe(t *testing.T) {
	var shadow *Shadow
	shadow.Publish("segment-a", streamlog.Segment{})
	if err := shadow.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
