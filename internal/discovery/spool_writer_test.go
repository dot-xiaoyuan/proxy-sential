package discovery

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestSpoolWriterGroupsQueuedBatchesWithoutLosingEvents(t *testing.T) {
	queue := make(chan []byte, 20)
	for i := 0; i < 20; i++ {
		queue <- []byte(fmt.Sprintf(`[{"event_id":"%d"}]`, i))
	}
	close(queue)
	var ids []string
	writes := 0
	err := drainSpoolQueue(queue, func(raw []byte) error {
		writes++
		var events []map[string]string
		if err := json.Unmarshal(raw, &events); err != nil {
			return err
		}
		for _, e := range events {
			ids = append(ids, e["event_id"])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if writes >= 20 || len(ids) != 20 {
		t.Fatalf("writes=%d ids=%v", writes, ids)
	}
	for i, id := range ids {
		if id != fmt.Sprint(i) {
			t.Fatalf("event %d became %s", i, id)
		}
	}
}

func TestSpoolWriterBoundsCombinedEvents(t *testing.T) {
	queue := make(chan []byte, 10)
	for i := 0; i < 10; i++ {
		events := make([]map[string]int, 250)
		for j := range events {
			events[j] = map[string]int{"id": i*250 + j}
		}
		raw, _ := json.Marshal(events)
		queue <- raw
	}
	close(queue)
	total, writes := 0, 0
	err := drainSpoolQueue(queue, func(raw []byte) error {
		var events []json.RawMessage
		if e := json.Unmarshal(raw, &events); e != nil {
			return e
		}
		if len(events) > 2000 || len(raw) > 8<<20 {
			t.Fatal("batch budget exceeded")
		}
		total += len(events)
		writes++
		return nil
	})
	if err != nil || total != 2500 || writes != 2 {
		t.Fatalf("total=%d writes=%d err=%v", total, writes, err)
	}
}

func TestSpoolWriterReportsDurabilityFailure(t *testing.T) {
	queue := make(chan []byte, 1)
	queue <- []byte(`[{"event_id":"1"}]`)
	close(queue)
	failure := fmt.Errorf("disk sync failed")
	if err := drainSpoolQueue(queue, func([]byte) error { return failure }); err != failure {
		t.Fatalf("got %v", err)
	}
}

func TestStreamSpoolWriterNeverCombinesBeyondSegmentBudget(t *testing.T) {
	queue := make(chan []byte, 8)
	for i := 0; i < 8; i++ {
		batch := make([]map[string]int, 250)
		for at := range batch {
			batch[at] = map[string]int{"id": i*250 + at}
		}
		raw, _ := json.Marshal(batch)
		queue <- raw
	}
	close(queue)
	total, writes := 0, 0
	err := drainSpoolQueueBounded(queue, func(raw []byte) error {
		var batch []json.RawMessage
		if err := json.Unmarshal(raw, &batch); err != nil {
			return err
		}
		if len(batch) > streamlog.MaxSegmentEvents || len(raw) > 1<<20 {
			t.Fatal("stream segment exceeds capture budget")
		}
		total += len(batch)
		writes++
		return nil
	}, streamlog.MaxSegmentEvents, 1<<20)
	if err != nil || total != 2000 || writes != 2 {
		t.Fatalf("stream combine: total=%d writes=%d err=%v", total, writes, err)
	}
}

func TestStreamSpoolWriterGathersNextCaptureWindow(t *testing.T) {
	queue := make(chan []byte, 2)
	firstCommitting := make(chan struct{})
	releaseFirst := make(chan struct{})
	var batches [][]int
	done := make(chan error, 1)
	go func() {
		done <- drainSpoolQueueBoundedWindow(queue, func(raw []byte) error {
			var batch []struct {
				ID int `json:"id"`
			}
			if err := json.Unmarshal(raw, &batch); err != nil {
				return err
			}
			ids := make([]int, len(batch))
			for i, event := range batch {
				ids[i] = event.ID
			}
			batches = append(batches, ids)
			if len(batches) == 1 {
				close(firstCommitting)
				<-releaseFirst
			}
			return nil
		}, streamlog.MaxSegmentEvents, 1<<20, 500*time.Millisecond)
	}()
	queue <- []byte(`[{"id":0}]`)
	<-firstCommitting
	for batch := 0; batch < 2; batch++ {
		entries := make([]map[string]int, captureFlushEvents)
		for i := range entries {
			entries[i] = map[string]int{"id": batch*captureFlushEvents + i + 1}
		}
		raw, _ := json.Marshal(entries)
		queue <- raw
		if batch == 0 {
			close(releaseFirst)
			time.Sleep(20 * time.Millisecond)
		}
	}
	close(queue)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[0]) != 1 || len(batches[1]) != 2*captureFlushEvents {
		t.Fatalf("batch sizes: %v", batches)
	}
	for i, id := range batches[1] {
		if id != i+1 {
			t.Fatalf("event %d became %d", i+1, id)
		}
	}
}
