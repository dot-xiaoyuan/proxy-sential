package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"proxy-sentinel/internal/normalized"
)

type normalizedRetryWriter struct {
	events []normalized.Event
	err    error
	strict bool
}

func (w *normalizedRetryWriter) WriteEventBusNormalizedEvents(_ context.Context, events []normalized.Event) error {
	w.events = events
	w.strict = true
	return w.err
}

func TestNormalizedOnlySinkPreservesEventsAndPropagatesRetry(t *testing.T) {
	body := json.RawMessage(`{"event_id":"discovery-1","type":"discovery","observer":{"sensor_id":"mirror-1"}}`)
	raw, err := json.Marshal(Envelope{Event: body})
	if err != nil {
		t.Fatal(err)
	}
	failed := errors.New("storage unavailable")
	w := &normalizedRetryWriter{err: failed}
	sink := NewClickHouseNormalizedSink(w)
	receipts := []Receipt{{EventID: "discovery-1", Envelope: raw}}
	if err := sink.WriteReceipts(context.Background(), receipts); !errors.Is(err, failed) {
		t.Fatalf("writer error must prevent offset commit: %v", err)
	}
	w.err = nil
	if err := sink.WriteReceipts(context.Background(), receipts); err != nil {
		t.Fatal(err)
	}
	if len(w.events) != 1 || w.events[0].EventID != "discovery-1" || w.events[0].Observer["sensor_id"] != "mirror-1" {
		t.Fatalf("normalized event lost on retry: %+v", w.events)
	}
	if !w.strict {
		t.Fatal("event bus sink bypassed strict event-ID check")
	}
}

func TestNormalizedOnlySinkRejectsInvalidBodyBeforeWritingBatch(t *testing.T) {
	valid, _ := json.Marshal(Envelope{Event: json.RawMessage(`{"event_id":"discovery-1","type":"discovery"}`)})
	invalid, _ := json.Marshal(Envelope{Event: json.RawMessage(`{"event_id":"discovery-2"}`)})
	w := &normalizedRetryWriter{}
	err := NewClickHouseNormalizedSink(w).WriteReceipts(context.Background(), []Receipt{{EventID: "discovery-1", Envelope: valid}, {EventID: "discovery-2", Envelope: invalid}})
	if err == nil || len(w.events) != 0 {
		t.Fatalf("invalid event body must prevent sink acknowledgement: err=%v written=%d", err, len(w.events))
	}
}

func TestNormalizedOnlySinkRejectsConflictingEventIDBeforeWriting(t *testing.T) {
	first, _ := json.Marshal(Envelope{Event: json.RawMessage(`{"event_id":"same","type":"discovery","payload":{"value":1}}`)})
	second, _ := json.Marshal(Envelope{Event: json.RawMessage(`{"event_id":"same","type":"discovery","payload":{"value":2}}`)})
	w := &normalizedRetryWriter{}
	err := NewClickHouseNormalizedSink(w).WriteReceipts(context.Background(), []Receipt{{EventID: "same", Envelope: first}, {EventID: "same", Envelope: second}})
	if err == nil || w.strict {
		t.Fatalf("conflicting event ID reached normalized writer: %v", err)
	}
}
