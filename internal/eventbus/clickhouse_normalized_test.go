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
}

func (w *normalizedRetryWriter) WriteNormalizedEvents(_ context.Context, events []normalized.Event) error {
	w.events = events
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
}
