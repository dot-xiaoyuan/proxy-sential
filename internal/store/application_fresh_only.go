package store

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

const applicationFreshCursorOverlap = 2 * time.Second

func applicationHistoryDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED")), "true")
}

func freshApplicationConnectionCursor(now time.Time) (applicationConnectionCursor, []byte, error) {
	cursor := applicationConnectionCursor{
		WrittenAt:    now.UTC().Add(-applicationFreshCursorOverlap).Format(time.RFC3339Nano),
		SensorID:     "\uffff",
		CampusID:     "\uffff",
		ConnectionID: "\uffff",
	}
	raw, err := json.Marshal(cursor)
	return cursor, raw, err
}

func freshApplicationObservationCursor(now time.Time) (applicationObservationCursor, []byte, error) {
	cursor := applicationObservationCursor{
		WrittenAt:   now.UTC().Add(-applicationFreshCursorOverlap).Format(time.RFC3339Nano),
		WindowStart: "9999-12-31T23:59:59Z",
		SensorID:    "\uffff",
		CampusID:    "\uffff",
	}
	raw, err := json.Marshal(cursor)
	return cursor, raw, err
}
