package discovery

import (
	"encoding/json"
	"fmt"
	"testing"
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
	queue := make(chan []byte, 4)
	for i := 0; i < 4; i++ {
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
		if len(batch) > 500 || len(raw) > 1<<20 {
			t.Fatal("stream segment exceeds capture budget")
		}
		total += len(batch)
		writes++
		return nil
	}, 500, 1<<20)
	if err != nil || total != 1000 || writes != 2 {
		t.Fatalf("stream combine: total=%d writes=%d err=%v", total, writes, err)
	}
}
