package eventbus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"proxy-sentinel/internal/normalized"
)

// normalizedEventWriter is implemented by store.ClickHouseStore. The bus path
// must check retained event IDs even when the general ingest path has opted
// into ClickHouse block-level deduplication.
type normalizedEventWriter interface {
	WriteEventBusNormalizedEvents(context.Context, []normalized.Event) error
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
	seen := make(map[string]string, len(receipts))
	for _, receipt := range receipts {
		var envelope Envelope
		if err := json.Unmarshal(receipt.Envelope, &envelope); err != nil {
			return fmt.Errorf("event-bus normalized sink decode event=%s: %w", receipt.EventID, err)
		}
		var event normalized.Event
		if err := json.Unmarshal(envelope.Event, &event); err != nil || event.EventID == "" || event.Type == "" {
			return fmt.Errorf("event-bus normalized sink invalid body event=%s: %w", receipt.EventID, errors.Join(err, errors.New("missing event id or type")))
		}
		if receipt.EventID != event.EventID || (envelope.EventID != "" && envelope.EventID != event.EventID) {
			return fmt.Errorf("event-bus normalized sink event ID conflicts with receipt")
		}
		bodyHash := sha256.Sum256(envelope.Event)
		digest := "sha256:" + hex.EncodeToString(bodyHash[:])
		if receipt.ContentHash != "" && receipt.ContentHash != digest || envelope.ContentHash != "" && envelope.ContentHash != digest {
			return fmt.Errorf("event-bus normalized sink content hash conflicts with receipt")
		}
		if prior, ok := seen[event.EventID]; ok && prior != digest {
			return fmt.Errorf("event-bus normalized sink batch has conflicting event ID %s", event.EventID)
		}
		seen[event.EventID] = digest
		events = append(events, event)
	}
	if len(events) == 0 {
		return nil
	}
	return s.writer.WriteEventBusNormalizedEvents(ctx, events)
}
