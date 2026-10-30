package eventbus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

const SchemaVersion = 1

// Envelope is the versioned wire contract for one standard event. The event
// body stays intact; the envelope carries the fixed identity and source
// position needed for replay, deduplication and auditing.
type Envelope struct {
	SchemaVersion int             `json:"schema_version"`
	EventID       string          `json:"event_id"`
	EventType     string          `json:"event_type"`
	SensorID      string          `json:"sensor_id"`
	ScopeID       string          `json:"scope_id"`
	PartitionKey  string          `json:"partition_key"`
	ObservedAt    time.Time       `json:"observed_at"`
	AcceptedAt    time.Time       `json:"accepted_at"`
	ContentHash   string          `json:"content_hash"`
	SegmentID     string          `json:"segment_id"`
	Source        string          `json:"source"`
	SourcePath    string          `json:"source_path"`
	Event         json.RawMessage `json:"event"`
}

// NewDiscoveryEnvelope builds one envelope from a captured segment event. The
// partition key is supplied by the discovery package so that the bus package
// does not depend on discovery business rules.
func NewDiscoveryEnvelope(segmentID string, segment streamlog.Segment, event normalized.Event, partitionKey string) (Envelope, error) {
	if strings.TrimSpace(segmentID) == "" {
		return Envelope{}, errors.New("event bus envelope requires a segment id")
	}
	if strings.TrimSpace(partitionKey) == "" {
		return Envelope{}, errors.New("event bus envelope requires a partition key")
	}
	if event.EventID == "" || event.Timestamp == "" {
		return Envelope{}, errors.New("event bus envelope requires event id and observation time")
	}
	if event.Type == "" {
		return Envelope{}, errors.New("event bus envelope requires event type")
	}
	if segment.AcceptedAt.IsZero() {
		return Envelope{}, errors.New("event bus envelope requires segment acceptance time")
	}
	observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return Envelope{}, fmt.Errorf("event bus envelope observation time: %w", err)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return Envelope{}, fmt.Errorf("event bus envelope payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return Envelope{
		SchemaVersion: SchemaVersion,
		EventID:       event.EventID,
		EventType:     event.Type,
		SensorID:      stringField(event.Observer, "sensor_id"),
		ScopeID:       stringField(event.Observer, "capture_scope_id"),
		PartitionKey:  partitionKey,
		ObservedAt:    observed.UTC(),
		AcceptedAt:    segment.AcceptedAt.UTC(),
		ContentHash:   "sha256:" + hex.EncodeToString(sum[:]),
		SegmentID:     segmentID,
		Source:        segment.Source,
		SourcePath:    segment.SourcePath,
		Event:         payload,
	}, nil
}

func (e Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

func (e Envelope) Key() []byte {
	return []byte(e.PartitionKey)
}

func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	value, _ := fields[key].(string)
	return strings.TrimSpace(value)
}
