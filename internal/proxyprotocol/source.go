package proxyprotocol

import (
	"context"
	"proxy-sentinel/internal/normalized"
	"time"
)

// Scan is a stable keyset page over event time, sensor and event ID. Each reconciliation
// scans the retained window again so late events are recovered without reclassification.
type Cursor struct {
	Timestamp string `json:"timestamp"`
	SensorID  string `json:"sensor_id"`
	EventID   string `json:"event_id"`
}
type Scan struct {
	From  time.Time
	To    time.Time
	After Cursor
	Limit int
}
type EventSource interface {
	ScanProxyEvents(context.Context, Scan) ([]normalized.Event, error)
}

func EventCursor(e normalized.Event) Cursor {
	return Cursor{e.Timestamp, Text(e.Observer, "sensor_id"), e.EventID}
}
func CursorLess(a, b Cursor) bool {
	ta, _ := time.Parse(time.RFC3339Nano, a.Timestamp)
	tb, _ := time.Parse(time.RFC3339Nano, b.Timestamp)
	if !ta.Equal(tb) {
		return ta.Before(tb)
	}
	if a.SensorID != b.SensorID {
		return a.SensorID < b.SensorID
	}
	return a.EventID < b.EventID
}
