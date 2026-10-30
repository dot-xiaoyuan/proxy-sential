package eventbus

import (
	"context"
	"encoding/json"
	"log"

	"proxy-sentinel/internal/normalized"
)

// normalizedEventWriter is implemented by store.ClickHouseStore.
type normalizedEventWriter interface {
	WriteNormalizedEvents(context.Context, []normalized.Event) error
}

// ClickHouseNormalizedSink bridges the versioned event bus back into the
// normalized event table. The old ingest sources were transferred to the stream
// owner, so this is the single place that keeps activity/risk read models fed
// from the new bus without re-enabling the legacy file ingest.
type ClickHouseNormalizedSink struct {
	writer normalizedEventWriter
}

func NewClickHouseNormalizedSink(writer normalizedEventWriter) *ClickHouseNormalizedSink {
	return &ClickHouseNormalizedSink{writer: writer}
}

func (s *ClickHouseNormalizedSink) WriteReceipts(ctx context.Context, receipts []Receipt) error {
	if s == nil || s.writer == nil || len(receipts) == 0 {
		return nil
	}
	events := make([]normalized.Event, 0, len(receipts))
	for _, receipt := range receipts {
		var envelope Envelope
		if err := json.Unmarshal(receipt.Envelope, &envelope); err != nil {
			log.Printf("event-bus normalized sink: skip receipt event=%s: %v", receipt.EventID, err)
			continue
		}
		var event normalized.Event
		if err := json.Unmarshal(envelope.Event, &event); err != nil || event.EventID == "" || event.Type == "" {
			log.Printf("event-bus normalized sink: skip envelope event=%s: invalid event body", receipt.EventID)
			continue
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		return nil
	}
	return s.writer.WriteNormalizedEvents(ctx, events)
}
