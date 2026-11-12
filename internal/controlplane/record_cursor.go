package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type recordCursor struct {
	Snapshot time.Time `json:"snapshot"`
	At       time.Time `json:"at"`
	ID       string    `json:"id"`
}

func decodeRecordCursor(value string) (recordCursor, error) {
	var cursor recordCursor
	if value == "" {
		return cursor, nil
	}
	if len(value) > 1024 {
		return cursor, fmt.Errorf("invalid cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Snapshot.IsZero() || cursor.At.IsZero() || cursor.ID == "" {
		return recordCursor{}, fmt.Errorf("invalid cursor")
	}
	return cursor, nil
}

func encodeRecordCursor(cursor recordCursor) string {
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}
