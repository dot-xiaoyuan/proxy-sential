package discovery

import (
	"time"

	"proxy-sentinel/internal/normalized"
)

// Capture groups only short, identical, positive-TTL announcements. The first
// and last producer observations remain in the one durable source event.
const passiveCaptureCoalesceWindow = time.Second

type captureCoalescer struct {
	events    []normalized.Event
	positions map[string]int
}

func newCaptureCoalescer() *captureCoalescer {
	return &captureCoalescer{positions: map[string]int{}}
}

func captureCoalesceKey(event normalized.Event) (string, bool) {
	if len(event.RawRef) != 0 || event.Payload == nil || event.Payload["withdrawn"] == true || number(event.Payload, "ttl") <= 0 {
		return "", false
	}
	payload := make(map[string]any, len(event.Payload))
	for key, value := range event.Payload {
		if key != "ttl" {
			payload[key] = value
		}
	}
	return contentHash([]any{event.Type, event.Source, event.SourceEventType, event.Observer, event.Subject, payload, event.Confidence}), true
}

func (c *captureCoalescer) add(event normalized.Event) bool {
	key, eligible := captureCoalesceKey(event)
	if eligible {
		if at, found := c.positions[key]; found {
			previous := c.events[at]
			first := previous.Timestamp
			firstID := previous.EventID
			count := 1
			if previous.RawRef != nil {
				if value, ok := previous.RawRef["coalesced_first_observed_at"].(string); ok {
					first = value
				}
				if value, ok := previous.RawRef["coalesced_first_producer_event_id"].(string); ok {
					firstID = value
				}
				if value, ok := previous.RawRef["coalesced_count"].(int); ok {
					count = value
				}
			}
			firstAt, firstErr := time.Parse(time.RFC3339Nano, first)
			previousAt, previousErr := time.Parse(time.RFC3339Nano, previous.Timestamp)
			currentAt, currentErr := time.Parse(time.RFC3339Nano, event.Timestamp)
			if firstErr == nil && previousErr == nil && currentErr == nil && !currentAt.Before(previousAt) &&
				currentAt.Sub(firstAt) <= passiveCaptureCoalesceWindow {
				event.RawRef = cloneStreamFields(event.RawRef)
				event.RawRef["coalesced_count"] = count + 1
				event.RawRef["coalesced_first_observed_at"] = first
				event.RawRef["coalesced_first_producer_event_id"] = firstID
				c.events[at] = event
				return true
			}
		}
		c.positions[key] = len(c.events)
	}
	c.events = append(c.events, event)
	return false
}

func (c *captureCoalescer) len() int { return len(c.events) }

func (c *captureCoalescer) drain() []normalized.Event {
	events := c.events
	c.events = nil
	c.positions = map[string]int{}
	return events
}
