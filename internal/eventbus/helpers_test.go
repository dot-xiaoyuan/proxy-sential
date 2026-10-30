package eventbus

import (
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func testEvent(id string, at time.Time) normalized.Event {
	return normalized.Event{
		SchemaVersion: "1.0",
		EventID:       id,
		Source:        "test",
		Type:          "discovery",
		Timestamp:     at.Format(time.RFC3339Nano),
		Observer: map[string]any{
			"sensor_id":        "sensor-a",
			"capture_scope_id": "scope-a",
		},
		Subject: map[string]any{
			"ip":     "198.51.100.10",
			"mac":    "02:00:00:00:00:10",
			"site":   "site-a",
			"domain": "domain-a",
		},
		Payload:    map[string]any{"origin": "ssdp", "ttl": 600},
		Confidence: 1,
	}
}

func testSegment(at time.Time, events ...normalized.Event) streamlog.Segment {
	return streamlog.Segment{
		Source:     "test",
		SourcePath: "test://scope-a/passive",
		AcceptedAt: at,
		Events:     events,
	}
}
