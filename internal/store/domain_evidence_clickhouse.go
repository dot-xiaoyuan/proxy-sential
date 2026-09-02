package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

func (s *ClickHouseStore) ListDomainEventsAfter(ctx context.Context, sensorID, since, cursorTimestamp, cursorEventID string, limit int) ([]normalized.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	start, err := time.Parse(time.RFC3339Nano, since)
	if err != nil {
		return nil, fmt.Errorf("invalid domain backfill start: %w", err)
	}
	clauses := []string{"timestamp >= parseDateTime64BestEffort(" + chQuote(start.UTC().Format(time.RFC3339Nano)) + ",6,'UTC')", "type IN ('dns','tls','quic','http')", "multiIf(type='dns',JSONExtractString(payload_json,'query'),type='http',JSONExtractString(payload_json,'host'),JSONExtractString(payload_json,'sni')) != ''"}
	if strings.TrimSpace(sensorID) != "" {
		clauses = append(clauses, "sensor_id="+chQuote(strings.TrimSpace(sensorID)))
	}
	if strings.TrimSpace(cursorTimestamp) != "" {
		cursor, parseErr := time.Parse(time.RFC3339Nano, cursorTimestamp)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid domain backfill cursor: %w", parseErr)
		}
		clauses = append(clauses, "(timestamp,event_id) > (parseDateTime64BestEffort("+chQuote(cursor.UTC().Format(time.RFC3339Nano))+",6,'UTC'),"+chQuote(cursorEventID)+")")
	}
	data, err := s.query(ctx, fmt.Sprintf(`
SELECT formatDateTime(timestamp,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') event_timestamp,event_id,schema_version,source,source_event_type,type,subject_ip,endpoint_id,auth_session_id,payload_json,flow_json
FROM normalized_events
WHERE %s
ORDER BY timestamp,event_id
LIMIT %d
FORMAT JSONEachRow`, strings.Join(clauses, " AND "), limit))
	if err != nil {
		return nil, err
	}
	items := []normalized.Event{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var row struct {
			Timestamp       string `json:"event_timestamp"`
			EventID         string `json:"event_id"`
			SchemaVersion   string `json:"schema_version"`
			Source          string `json:"source"`
			SourceEventType string `json:"source_event_type"`
			Type            string `json:"type"`
			SubjectIP       string `json:"subject_ip"`
			EndpointID      string `json:"endpoint_id"`
			AuthSessionID   string `json:"auth_session_id"`
			PayloadJSON     string `json:"payload_json"`
			FlowJSON        string `json:"flow_json"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		payload, flow := map[string]any{}, map[string]any{}
		_ = json.Unmarshal([]byte(row.PayloadJSON), &payload)
		_ = json.Unmarshal([]byte(row.FlowJSON), &flow)
		if row.AuthSessionID != "" {
			payload["session_id"] = row.AuthSessionID
		}
		subject := map[string]any{"ip": row.SubjectIP}
		if row.EndpointID != "" {
			subject["endpoint_id"] = row.EndpointID
		}
		items = append(items, normalized.Event{Timestamp: normalizeClickHouseTimestamp(row.Timestamp), EventID: row.EventID, SchemaVersion: row.SchemaVersion, Source: row.Source, SourceEventType: row.SourceEventType, Type: row.Type, Subject: subject, Payload: payload, Flow: flow})
	}
	return items, scanner.Err()
}
