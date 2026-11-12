package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

// normalized_events currently expires seven days after the observation time.
// Leave a full day of margin for cleanup and clock uncertainty. An older ID
// cannot be proved absent from the retained body, so the canary must stop.
const eventBusIDProofWindow = 6 * 24 * time.Hour

// WriteEventBusNormalizedEvents performs an immediate read-before-insert for
// the reliable canary, independent of the global block-dedup setting. The
// old normalized_event_ids materialized views are no longer populated, so a
// bus replay must query the retained normalized_events body itself. This is
// deliberately bounded and may backpressure the canary on a slow ClickHouse.
func (s *ClickHouseStore) WriteEventBusNormalizedEvents(ctx context.Context, events []normalized.Event) error {
	if len(events) == 0 {
		return nil
	}
	if len(events) > 2000 {
		return errors.New("event bus normalized batch exceeds 2000 events")
	}
	seen := make(map[string][]byte, len(events))
	for _, event := range events {
		if event.EventID == "" {
			return errors.New("event bus normalized event has no ID")
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if prior, ok := seen[event.EventID]; ok && !bytes.Equal(prior, encoded) {
			return fmt.Errorf("event bus batch has conflicting content for event ID %s", event.EventID)
		}
		seen[event.EventID] = encoded
	}
	events = uniqueEventsByID(events)
	existing, err := s.eventBusExistingIDs(ctx, events)
	if err != nil {
		return fmt.Errorf("check event bus event IDs: %w", err)
	}
	pending := make([]normalized.Event, 0, len(events))
	for _, event := range events {
		if _, found := existing[event.EventID]; !found {
			pending = append(pending, event)
		}
	}
	return s.insertEventBusNormalizedSync(ctx, pending)
}

func (s *ClickHouseStore) insertEventBusNormalizedSync(ctx context.Context, events []normalized.Event) error {
	if len(events) == 0 {
		return nil
	}
	parsed, err := url.Parse(s.dsn)
	if err != nil {
		return err
	}
	params := parsed.Query()
	params.Set("async_insert", "0")
	params.Set("wait_for_async_insert", "1")
	parsed.RawQuery = params.Encode()
	// Reuse the existing row encoder without mutating the shared store or its
	// request URL while other ingestion paths run concurrently.
	synchronous := *s
	synchronous.dsn = parsed.String()
	return synchronous.insertNormalizedEvents(ctx, events)
}

func (s *ClickHouseStore) eventBusExistingIDs(ctx context.Context, events []normalized.Event) (map[string]struct{}, error) {
	now := time.Now().UTC()
	for _, event := range events {
		observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("event bus event %s has invalid observation time: %w", event.EventID, err)
		}
		if observed.Before(now.Add(-eventBusIDProofWindow)) {
			return nil, fmt.Errorf("event bus event %s is outside the retained normalized event ID proof window; replay requires an authoritative archive", event.EventID)
		}
		if observed.After(now.Add(time.Hour)) {
			return nil, fmt.Errorf("event bus event %s observation time is more than an hour in the future", event.EventID)
		}
	}
	found := make(map[string]struct{}, len(events))
	for offset := 0; offset < len(events); offset += 100 {
		end := offset + 100
		if end > len(events) {
			end = len(events)
		}
		ids := make([]string, 0, end-offset)
		expected := make(map[string]string, end-offset)
		for _, event := range events[offset:end] {
			ids = append(ids, chQuote(event.EventID))
			fingerprint, err := eventBusComparableEvent(event)
			if err != nil {
				return nil, fmt.Errorf("event bus event %s: %w", event.EventID, err)
			}
			expected[event.EventID] = fingerprint
		}
		query := "SELECT event_id,schema_version,source,source_event_type,type," +
			"formatDateTime(timestamp,'%Y-%m-%dT%H:%i:%S.%fZ','UTC') AS event_timestamp," +
			"observer_json,subject_json,payload_json,flow_json,raw_ref_json,confidence " +
			"FROM normalized_events PREWHERE timestamp>=parseDateTime64BestEffort(" +
			chQuote(now.Add(-7*24*time.Hour-time.Minute).Format(time.RFC3339Nano)) + ",6) AND timestamp<parseDateTime64BestEffort(" +
			chQuote(now.Add(time.Hour+time.Minute).Format(time.RFC3339Nano)) + ",6) WHERE event_id IN (" +
			strings.Join(ids, ",") + ") LIMIT 201 SETTINGS max_threads=1,max_memory_usage=268435456,max_result_bytes=67108864,max_execution_time=20 FORMAT JSONEachRow"
		data, err := s.query(ctx, query)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), 16<<20)
		rows := 0
		for scanner.Scan() {
			rows++
			if rows > 200 {
				return nil, errors.New("event bus ID lookup exceeded 200 retained rows")
			}
			var row eventBusNormalizedRow
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				return nil, err
			}
			want, ok := expected[row.EventID]
			if !ok {
				return nil, errors.New("event bus ID lookup returned an unexpected event")
			}
			actual, err := row.comparableEvent()
			if err != nil {
				return nil, fmt.Errorf("event bus existing event %s cannot be compared: %w", row.EventID, err)
			}
			if actual != want {
				return nil, fmt.Errorf("event bus event ID %s conflicts with retained normalized body", row.EventID)
			}
			found[row.EventID] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return found, nil
}

type eventBusNormalizedRow struct {
	EventID    string  `json:"event_id"`
	Schema     string  `json:"schema_version"`
	Source     string  `json:"source"`
	SourceType string  `json:"source_event_type"`
	Type       string  `json:"type"`
	Timestamp  string  `json:"event_timestamp"`
	Observer   string  `json:"observer_json"`
	Subject    string  `json:"subject_json"`
	Payload    string  `json:"payload_json"`
	Flow       string  `json:"flow_json"`
	RawRef     string  `json:"raw_ref_json"`
	Confidence float64 `json:"confidence"`
}

func (r eventBusNormalizedRow) comparableEvent() (string, error) {
	event := normalized.Event{
		EventID: r.EventID, SchemaVersion: r.Schema, Source: r.Source,
		SourceEventType: r.SourceType, Type: r.Type, Timestamp: r.Timestamp,
		Confidence: r.Confidence,
	}
	for _, item := range []struct {
		value  string
		target *map[string]any
	}{{r.Observer, &event.Observer}, {r.Subject, &event.Subject}, {r.Payload, &event.Payload}, {r.Flow, &event.Flow}, {r.RawRef, &event.RawRef}} {
		if item.value == "" {
			return "", errors.New("retained normalized body has an empty JSON field")
		}
		if err := json.Unmarshal([]byte(item.value), item.target); err != nil {
			return "", err
		}
	}
	return eventBusComparableEvent(event)
}

// Compare exactly the fields persisted by insertNormalizedEvents. The table
// stores timestamps at microsecond precision and absent maps as JSON {}.
func eventBusComparableEvent(event normalized.Event) (string, error) {
	observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return "", err
	}
	event.Timestamp = observed.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	for _, field := range []*map[string]any{&event.Observer, &event.Subject, &event.Payload, &event.Flow, &event.RawRef} {
		if *field == nil {
			*field = map[string]any{}
		}
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
