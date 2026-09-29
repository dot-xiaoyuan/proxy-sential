package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"sort"
	"time"
)

func (s *FileStore) ScanProxyEvents(ctx context.Context, q proxyprotocol.Scan) ([]normalized.Event, error) {
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
			if e.Type != "proxy_transaction" {
				continue
			}
			c := proxyprotocol.EventCursor(e)
			key := c.SensorID + "\x00" + c.EventID
			if seen[key] || q.After.Timestamp != "" && !proxyprotocol.CursorLess(q.After, c) {
				continue
			}
			seen[key] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return proxyprotocol.CursorLess(proxyprotocol.EventCursor(out[i]), proxyprotocol.EventCursor(out[j]))
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}
func (s *DBStore) ScanProxyEvents(ctx context.Context, q proxyprotocol.Scan) ([]normalized.Event, error) {
	return s.ch.ScanProxyEvents(ctx, q)
}
func (s *ClickHouseStore) ScanProxyEvents(ctx context.Context, q proxyprotocol.Scan) ([]normalized.Event, error) {
	limit := q.Limit
	if limit <= 0 || limit > 2000 {
		limit = 1000
	}
	where := "timestamp >= parseDateTime64BestEffort(" + chQuote(q.From.Format(time.RFC3339Nano)) + ") AND timestamp < parseDateTime64BestEffort(" + chQuote(q.To.Format(time.RFC3339Nano)) + ") AND type = 'proxy_transaction'"
	if q.After.Timestamp != "" {
		if _, err := time.Parse(time.RFC3339Nano, q.After.Timestamp); err != nil {
			return nil, err
		}
		where += " AND (timestamp,sensor_id,event_id) > (parseDateTime64BestEffort(" + chQuote(q.After.Timestamp) + ")," + chQuote(q.After.SensorID) + "," + chQuote(q.After.EventID) + ")"
	}
	data, err := s.query(ctx, fmt.Sprintf(`SELECT DISTINCT timestamp,sensor_id,campus_id,event_id,type,subject_ip,source,raw_ref_json,observer_json,payload_json,flow_json FROM normalized_events WHERE %s ORDER BY timestamp,sensor_id,event_id LIMIT %d FORMAT JSONEachRow`, where, limit))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Source    string `json:"source"`
		RawRef    string `json:"raw_ref_json"`
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
		e := normalized.Event{Source: row.Source, SchemaVersion: "v1", EventID: row.EventID, Timestamp: normalizeClickHouseTimestamp(row.Timestamp), Type: row.Type, Subject: map[string]any{"ip": row.SubjectIP, "campus_id": row.CampusID}, Observer: map[string]any{}}
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
		if err := json.Unmarshal([]byte(row.RawRef), &e.RawRef); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
