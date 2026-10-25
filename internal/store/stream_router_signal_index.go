package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/streamlog"
)

type StreamRouterSignalRef struct {
	IndexedAt  time.Time
	ObservedAt time.Time
	EventKey   string
	Protocol   string
	Body       StreamBodyRef
}

// ListStreamRouterSignalRefs reads only the indexed, selected router inputs.
// The insertion-time cursor includes late observations without scanning the
// authoritative body table or re-reading an entire rule window.
func (s *ClickHouseStore) ListStreamRouterSignalRefs(ctx context.Context, sensor string, after time.Time, afterKey string, limit int) ([]StreamRouterSignalRef, error) {
	if s == nil || sensor == "" || limit < 1 || limit > 100 || (after.IsZero() && afterKey != "") {
		return nil, errors.New("invalid router stream index cursor")
	}
	where := "sensor_id=" + chQuote(sensor)
	if !after.IsZero() {
		stamp := "parseDateTime64BestEffort(" + chQuote(after.UTC().Format(time.RFC3339Nano)) + ",6)"
		where += " AND (indexed_at>" + stamp + " OR (indexed_at=" + stamp + " AND event_key>" + chQuote(afterKey) + "))"
	}
	query := fmt.Sprintf(`SELECT indexed_at,event_key,scope_id,content_sha256,archive_month,retention_class,observed_at,protocol,body_ref
FROM stream_router_signal_index WHERE %s ORDER BY indexed_at,event_key LIMIT %d
SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=10 FORMAT JSONEachRow`, where, limit)
	data, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	result := make([]StreamRouterSignalRef, 0, limit)
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			IndexedAt  string `json:"indexed_at"`
			EventKey   string `json:"event_key"`
			Scope      string `json:"scope_id"`
			Hash       string `json:"content_sha256"`
			Month      uint32 `json:"archive_month"`
			Class      string `json:"retention_class"`
			ObservedAt string `json:"observed_at"`
			Protocol   string `json:"protocol"`
			BodyRef    string `json:"body_ref"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, err
		}
		indexed, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.IndexedAt))
		if err != nil {
			return nil, err
		}
		observed, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.ObservedAt))
		if err != nil {
			return nil, err
		}
		ref, err := ParseStreamBodyRef(row.BodyRef)
		if err != nil {
			return nil, err
		}
		if ref.Key != row.EventKey || ref.Scope != row.Scope || ref.SHA256 != row.Hash || ref.Class != row.Class || ref.Month != fmt.Sprint(row.Month) || row.EventKey == "" || row.Protocol == "" || len(result) >= limit {
			return nil, streamlog.ErrContentConflict
		}
		if !after.IsZero() && (indexed.Before(after) || (indexed.Equal(after) && row.EventKey <= afterKey)) {
			return nil, streamlog.ErrContentConflict
		}
		if len(result) > 0 {
			last := result[len(result)-1]
			if indexed.Before(last.IndexedAt) || (indexed.Equal(last.IndexedAt) && row.EventKey < last.EventKey) {
				return nil, streamlog.ErrContentConflict
			}
		}
		result = append(result, StreamRouterSignalRef{IndexedAt: indexed.UTC(), ObservedAt: observed.UTC(), EventKey: row.EventKey, Protocol: row.Protocol, Body: ref})
	}
	return result, nil
}
