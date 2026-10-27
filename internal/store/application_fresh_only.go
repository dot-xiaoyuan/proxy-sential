package store

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

const applicationFreshCursorOverlap = 2 * time.Second

func applicationHistoryDisabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED")), "true") {
		return true
	}
	// Fresh-only identity cutovers also exclude the historical application
	// reconciliation loop. This prevents a fresh deployment from starting a
	// seven-day normalized_events scan in the control plane.
	return strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_IDENTITY_POLICY_FRESH_ONLY")), "true")
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
