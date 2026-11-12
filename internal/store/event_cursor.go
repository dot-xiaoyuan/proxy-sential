package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const maxEventPageSize = 50

// An event cursor freezes the time range and the last ordered key. It is bound
// to the filters, but not to the page size, so a change of size starts a fresh
// page in the UI without making the cursor format depend on presentation.
type eventListCursor struct {
	Version int      `json:"v"`
	Filter  string   `json:"f"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	After   eventKey `json:"after"`
}

type eventKey struct {
	Timestamp string `json:"timestamp"`
	EventID   string `json:"event_id"`
	SensorID  string `json:"sensor_id"`
}

func eventListFingerprint(query Query) string {
	query.Limit = 0
	query.Cursor = 0
	query.EventCursor = ""
	query.InventoryCursor = ""
	query.InventoryPositionPage = 0
	query.InventorySkipMetadata = false
	query.InventoryMetadataOnly = false
	encoded, _ := json.Marshal(query)
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func prepareEventListQuery(query Query, now time.Time) (Query, eventListCursor, error) {
	if query.Cursor != 0 {
		return Query{}, eventListCursor{}, fmt.Errorf("event list offsets are unsupported; use next_cursor")
	}
	fingerprint := eventListFingerprint(query)
	if query.EventCursor != "" {
		if len(query.EventCursor) > 2048 {
			return Query{}, eventListCursor{}, fmt.Errorf("event cursor is too long")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(query.EventCursor)
		if err != nil {
			return Query{}, eventListCursor{}, fmt.Errorf("invalid event cursor: %w", err)
		}
		var cursor eventListCursor
		if err = json.Unmarshal(decoded, &cursor); err != nil {
			return Query{}, eventListCursor{}, fmt.Errorf("invalid event cursor: %w", err)
		}
		if cursor.Version != 1 || cursor.Filter != fingerprint || cursor.To == "" || cursor.After.Timestamp == "" || cursor.After.EventID == "" {
			return Query{}, eventListCursor{}, fmt.Errorf("event cursor does not match this filter")
		}
		if _, err = time.Parse(time.RFC3339Nano, cursor.To); err != nil {
			return Query{}, eventListCursor{}, fmt.Errorf("invalid event cursor time: %w", err)
		}
		if _, err = time.Parse(time.RFC3339Nano, cursor.After.Timestamp); err != nil {
			return Query{}, eventListCursor{}, fmt.Errorf("invalid event cursor key: %w", err)
		}
		query.From, query.To, query.Window = cursor.From, cursor.To, ""
		return query, cursor, nil
	}
	cursor := eventListCursor{Version: 1, Filter: fingerprint}
	if query.From != "" {
		if _, err := time.Parse(time.RFC3339Nano, query.From); err != nil {
			return Query{}, eventListCursor{}, fmt.Errorf("bad from: %w", err)
		}
		cursor.From = query.From
	}
	if query.To != "" {
		if _, err := time.Parse(time.RFC3339Nano, query.To); err != nil {
			return Query{}, eventListCursor{}, fmt.Errorf("bad to: %w", err)
		}
		cursor.To = query.To
	} else {
		cursor.To = now.UTC().Format(time.RFC3339Nano)
	}
	if query.Window != "" && query.From == "" && query.To == "" {
		_, duration, err := NormalizeActivityWindow(query.Window)
		if err != nil {
			return Query{}, eventListCursor{}, err
		}
		cursor.From = now.UTC().Add(-duration).Format(time.RFC3339Nano)
	}
	query.From, query.To, query.Window = cursor.From, cursor.To, ""
	return query, cursor, nil
}

func encodeEventListCursor(cursor eventListCursor, after eventKey) *string {
	cursor.After = after
	encoded, _ := json.Marshal(cursor)
	value := base64.RawURLEncoding.EncodeToString(encoded)
	return &value
}

func eventKeyBefore(left, right eventKey) bool {
	leftTime, leftErr := time.Parse(time.RFC3339Nano, left.Timestamp)
	rightTime, rightErr := time.Parse(time.RFC3339Nano, right.Timestamp)
	if leftErr == nil && rightErr == nil && !leftTime.Equal(rightTime) {
		return leftTime.Before(rightTime)
	}
	if left.EventID != right.EventID {
		return strings.Compare(left.EventID, right.EventID) < 0
	}
	return strings.Compare(left.SensorID, right.SensorID) < 0
}

func normalizeEventKeyTimestamp(value string) (string, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano), nil
	}
	// normalized_events.timestamp is DateTime64(6,'Asia/Shanghai'). JSONEachRow
	// emits the column's wall time without a zone, so interpreting it as UTC
	// would move the next-page seek by eight hours.
	shanghai := time.FixedZone("Asia/Shanghai", 8*60*60)
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, value, shanghai); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano), nil
		}
	}
	return "", fmt.Errorf("invalid event key timestamp")
}
