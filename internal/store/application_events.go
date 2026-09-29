package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"proxy-sentinel/internal/appdomain"
	"proxy-sentinel/internal/normalized"
	"sort"
	"time"
)

func (s *FileStore) ScanApplicationEvents(ctx context.Context, q appdomain.Scan) ([]normalized.Event, error) {
	runs, err := s.runs(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []normalized.Event{}
	for _, run := range runs {
		events, err := readNormalizedEvents(ctx, filepath.Join(run.Dir, "normalized.jsonl"), Query{From: q.From.Format(time.RFC3339Nano), To: q.To.Format(time.RFC3339Nano), Limit: -1})
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			tm, parseErr := time.Parse(time.RFC3339Nano, e.Timestamp)
			if parseErr != nil || tm.Before(q.From) || !tm.Before(q.To) {
				continue
			}
			if e.Type != "dns" && e.Type != "http" && e.Type != "tls" && e.Type != "quic" && e.Type != "flow" {
				continue
			}
			c := appdomain.EventCursor(e)
			key := c.SensorID + "\x00" + c.EventID
			if seen[key] || q.After.Timestamp != "" && !appdomain.CursorLess(q.After, c) {
				continue
			}
			seen[key] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return appdomain.CursorLess(appdomain.EventCursor(out[i]), appdomain.EventCursor(out[j]))
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (s *DBStore) ScanApplicationEvents(ctx context.Context, q appdomain.Scan) ([]normalized.Event, error) {
	return s.ch.ScanApplicationEvents(ctx, q)
}
func (s *ClickHouseStore) ScanApplicationEvents(ctx context.Context, q appdomain.Scan) ([]normalized.Event, error) {
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	where := "timestamp >= parseDateTime64BestEffort(" + chQuote(q.From.Format(time.RFC3339Nano)) + ",9) AND timestamp < parseDateTime64BestEffort(" + chQuote(q.To.Format(time.RFC3339Nano)) + ",9) AND type IN ('dns','http','tls','quic','flow')"
	if q.After.Timestamp != "" {
		if _, err := time.Parse(time.RFC3339Nano, q.After.Timestamp); err != nil {
			return nil, err
		}
		where += " AND (timestamp,sensor_id,event_id) > (parseDateTime64BestEffort(" + chQuote(q.After.Timestamp) + ",9)," + chQuote(q.After.SensorID) + "," + chQuote(q.After.EventID) + ")"
	}
	// Select the bounded page of keys before fetching JSON payloads. Sorting full
	// payloads for the whole retained window scales with history size.
	keys := fmt.Sprintf("SELECT timestamp,sensor_id,event_id FROM normalized_events WHERE %s GROUP BY timestamp,sensor_id,event_id ORDER BY timestamp,sensor_id,event_id LIMIT %d", where, limit)
	data, err := s.query(ctx, `SELECT timestamp,sensor_id,event_id,tupleElement(v,1) AS campus_id,tupleElement(v,2) AS type,tupleElement(v,3) AS subject_ip,tupleElement(v,4) AS observer_json,tupleElement(v,5) AS payload_json,tupleElement(v,6) AS flow_json FROM (SELECT timestamp,sensor_id,event_id,argMin(tuple(campus_id,type,subject_ip,observer_json,payload_json,flow_json),tuple(campus_id,type,subject_ip,observer_json,payload_json,flow_json)) AS v FROM normalized_events PREWHERE `+where+` AND (timestamp,sensor_id,event_id) IN (`+keys+`) GROUP BY timestamp,sensor_id,event_id) ORDER BY timestamp,sensor_id,event_id SETTINGS max_threads=1,max_memory_usage=268435456,max_bytes_before_external_group_by=33554432,max_bytes_before_external_sort=33554432,max_execution_time=20 FORMAT JSONEachRow`)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Timestamp string `json:"timestamp"`
		SensorID  string `json:"sensor_id"`
		CampusID  string `json:"campus_id"`
		EventID   string `json:"event_id"`
		Type      string `json:"type"`
		SubjectIP string `json:"subject_ip"`
		Observer  string `json:"observer_json"`
		Payload   string `json:"payload_json"`
		Flow      string `json:"flow_json"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return nil, err
	}
	out := []normalized.Event{}
	for _, row := range rows {
		e := normalized.Event{SchemaVersion: "v1", EventID: row.EventID, Timestamp: normalizeClickHouseTimestamp(row.Timestamp), Type: row.Type, Subject: map[string]any{"ip": row.SubjectIP, "campus_id": row.CampusID}, Observer: map[string]any{}}
		if err := json.Unmarshal([]byte(row.Observer), &e.Observer); err != nil {
			return nil, err
		}
		if e.Observer == nil {
			e.Observer = map[string]any{}
		}
		e.Observer["sensor_id"] = row.SensorID
		if err := json.Unmarshal([]byte(row.Payload), &e.Payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(row.Flow), &e.Flow); err != nil {
			return nil, err
		}
		if parsed, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
			e.Timestamp = parsed.UTC().Format(time.RFC3339Nano)
		}
		out = append(out, e)
	}
	return out, nil
}
