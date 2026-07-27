package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
)

const ClickHouseDDLPath = "migrations/clickhouse/001_production_schema.sql"

type ClickHouseOptions struct {
	DSN string
}

type ClickHouseStore struct {
	dsn    string
	client *http.Client
}

func NewClickHouseStore(opts ClickHouseOptions) (*ClickHouseStore, error) {
	if err := dbRequired("clickhouse dsn", opts.DSN); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse clickhouse dsn: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("clickhouse dsn must be an http(s) URL for the HTTP interface")
	}
	return &ClickHouseStore{
		dsn:    opts.DSN,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *ClickHouseStore) DSN() string {
	return s.dsn
}

func (s *ClickHouseStore) WriteNormalizedEvents(ctx context.Context, events []normalized.Event) error {
	if len(events) == 0 {
		return nil
	}
	var body bytes.Buffer
	body.WriteString(`INSERT INTO normalized_events FORMAT JSONEachRow`)
	body.WriteByte('\n')
	for _, event := range events {
		row := map[string]any{
			"timestamp":         clickHouseTimestamp(event.Timestamp),
			"event_id":          event.EventID,
			"schema_version":    event.SchemaVersion,
			"source":            event.Source,
			"source_event_type": event.SourceEventType,
			"type":              event.Type,
			"sensor_id":         stringFromMap(event.Observer, "sensor_id"),
			"subject_ip":        stringFromMap(event.Subject, "ip"),
			"src_ip":            stringFromMap(event.Flow, "src_ip"),
			"dst_ip":            stringFromMap(event.Flow, "dst_ip"),
			"src_port":          uintFromMap(event.Flow, "src_port"),
			"dst_port":          uintFromMap(event.Flow, "dst_port"),
			"proto":             stringFromMap(event.Flow, "proto"),
			"direction":         stringFromMap(event.Flow, "direction"),
			"observer_json":     jsonString(event.Observer),
			"payload_json":      jsonString(event.Payload),
			"flow_json":         jsonString(event.Flow),
			"raw_ref_json":      jsonString(event.RawRef),
			"confidence":        event.Confidence,
		}
		if err := writeJSONLine(&body, row); err != nil {
			return err
		}
	}
	return s.exec(ctx, body.String())
}

func (s *ClickHouseStore) WriteIngestDiagnostics(ctx context.Context, diagnostics []ingest.Diagnostic) error {
	if len(diagnostics) == 0 {
		return nil
	}
	var body bytes.Buffer
	body.WriteString(`INSERT INTO ingest_diagnostics FORMAT JSONEachRow`)
	body.WriteByte('\n')
	for _, diagnostic := range diagnostics {
		row := map[string]any{
			"timestamp":         clickHouseTimestamp(diagnostic.Timestamp),
			"diagnostic_id":     diagnostic.DiagnosticID,
			"schema_version":    diagnostic.SchemaVersion,
			"sensor_id":         diagnostic.SensorID,
			"collector_kind":    diagnostic.Collector.Kind,
			"collector_version": diagnostic.Collector.Version,
			"interface_name":    diagnostic.Collector.Interface,
			"stage":             diagnostic.Stage,
			"type":              diagnostic.Type,
			"severity":          diagnostic.Severity,
			"summary":           diagnostic.Summary,
			"counters_json":     jsonString(diagnostic.Counters),
			"by_type_json":      jsonString(diagnostic.ByType),
			"raw_ref_json":      jsonString(diagnostic.RawRef),
			"details_json":      jsonString(diagnostic.Details),
		}
		if err := writeJSONLine(&body, row); err != nil {
			return err
		}
	}
	return s.exec(ctx, body.String())
}

func (s *ClickHouseStore) ListEventSamples(ctx context.Context, query Query) ([]normalized.Event, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	where := eventWhereSQL(query)
	sql := fmt.Sprintf(`
SELECT timestamp, event_id, schema_version, source, source_event_type, type, subject_ip, observer_json, payload_json, flow_json, raw_ref_json, confidence
FROM normalized_events%s
ORDER BY timestamp DESC, event_id DESC
LIMIT %d
FORMAT JSONEachRow`, where, limit)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return decodeEventRows(data)
}

func (s *ClickHouseStore) GetIPActivity(ctx context.Context, ip string, limit int) (ActivityProfile, error) {
	events, err := s.ListEventSamples(ctx, Query{Q: ip, Limit: defaultActivityEventLimit})
	if err != nil {
		return ActivityProfile{}, err
	}
	return BuildActivityProfile(ip, events, limit), nil
}

func (s *ClickHouseStore) GetEvent(ctx context.Context, eventID string) (normalized.Event, bool, error) {
	sql := fmt.Sprintf(`
SELECT timestamp, event_id, schema_version, source, source_event_type, type, subject_ip, observer_json, payload_json, flow_json, raw_ref_json, confidence
FROM normalized_events
WHERE event_id = %s
ORDER BY timestamp DESC
LIMIT 1
FORMAT JSONEachRow`, chQuote(eventID))
	data, err := s.query(ctx, sql)
	if err != nil {
		return normalized.Event{}, false, err
	}
	events, err := decodeEventRows(data)
	if err != nil {
		return normalized.Event{}, false, err
	}
	if len(events) == 0 {
		return normalized.Event{}, false, nil
	}
	return events[0], true, nil
}

func (s *ClickHouseStore) ListIngestDiagnostics(ctx context.Context, query Query) ([]ingest.Diagnostic, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	sql := fmt.Sprintf(`
SELECT timestamp, diagnostic_id, schema_version, sensor_id, collector_kind, collector_version, interface_name, stage, type, severity, summary, counters_json, by_type_json, raw_ref_json, details_json
FROM ingest_diagnostics
ORDER BY timestamp DESC, diagnostic_id DESC
LIMIT %d
FORMAT JSONEachRow`, limit)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return decodeDiagnosticRows(data)
}

func (s *ClickHouseStore) ListIngestErrors(ctx context.Context, limit int) ([]ingest.Diagnostic, error) {
	if limit == 0 {
		limit = 50
	}
	sql := fmt.Sprintf(`
SELECT timestamp, diagnostic_id, schema_version, sensor_id, collector_kind, collector_version, interface_name, stage, type, severity, summary, counters_json, by_type_json, raw_ref_json, details_json
FROM ingest_diagnostics
WHERE severity IN ('warning', 'error')
ORDER BY timestamp DESC, diagnostic_id DESC
LIMIT %d
FORMAT JSONEachRow`, limit)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return decodeDiagnosticRows(data)
}

func (s *ClickHouseStore) ListIngestEventTypes(ctx context.Context) ([]ingest.EventTypeCount, error) {
	data, err := s.query(ctx, `
SELECT type, count() AS count
FROM normalized_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY type
ORDER BY count DESC, type ASC
LIMIT 50
FORMAT JSONEachRow`)
	if err != nil {
		return nil, err
	}
	items := []ingest.EventTypeCount{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var row struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		items = append(items, ingest.EventTypeCount{Type: row.Type, Count: row.Count})
	}
	return items, scanner.Err()
}

func (s *ClickHouseStore) exec(ctx context.Context, sql string) error {
	_, err := s.query(ctx, sql)
	return err
}

func (s *ClickHouseStore) query(ctx context.Context, sql string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.dsn, strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse query failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func eventWhereSQL(query Query) string {
	clauses := []string{}
	if query.Q != "" {
		like := chQuote("%" + strings.ToLower(query.Q) + "%")
		clauses = append(clauses, "(lower(event_id) LIKE "+like+" OR lower(subject_ip) LIKE "+like+")")
	}
	if query.Level != "" {
		clauses = append(clauses, "type = "+chQuote(query.Level))
	}
	if query.SensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(query.SensorID))
	}
	if len(clauses) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(clauses, " AND ")
}

func decodeEventRows(data []byte) ([]normalized.Event, error) {
	events := []normalized.Event{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var row struct {
			Timestamp       string  `json:"timestamp"`
			EventID         string  `json:"event_id"`
			SchemaVersion   string  `json:"schema_version"`
			Source          string  `json:"source"`
			SourceEventType string  `json:"source_event_type"`
			Type            string  `json:"type"`
			SubjectIP       string  `json:"subject_ip"`
			ObserverJSON    string  `json:"observer_json"`
			PayloadJSON     string  `json:"payload_json"`
			FlowJSON        string  `json:"flow_json"`
			RawRefJSON      string  `json:"raw_ref_json"`
			Confidence      float64 `json:"confidence"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		event := normalized.Event{
			Timestamp:       row.Timestamp,
			EventID:         row.EventID,
			SchemaVersion:   row.SchemaVersion,
			Source:          row.Source,
			SourceEventType: row.SourceEventType,
			Type:            row.Type,
			Subject:         map[string]any{},
			Observer:        map[string]any{},
			Payload:         map[string]any{},
			Flow:            map[string]any{},
			RawRef:          map[string]any{},
			Confidence:      row.Confidence,
		}
		if row.SubjectIP != "" {
			event.Subject["ip"] = row.SubjectIP
		}
		_ = json.Unmarshal([]byte(row.ObserverJSON), &event.Observer)
		_ = json.Unmarshal([]byte(row.PayloadJSON), &event.Payload)
		_ = json.Unmarshal([]byte(row.FlowJSON), &event.Flow)
		_ = json.Unmarshal([]byte(row.RawRefJSON), &event.RawRef)
		events = append(events, event)
	}
	return events, scanner.Err()
}

func decodeDiagnosticRows(data []byte) ([]ingest.Diagnostic, error) {
	items := []ingest.Diagnostic{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var row struct {
			Timestamp        string `json:"timestamp"`
			DiagnosticID     string `json:"diagnostic_id"`
			SchemaVersion    string `json:"schema_version"`
			SensorID         string `json:"sensor_id"`
			CollectorKind    string `json:"collector_kind"`
			CollectorVersion string `json:"collector_version"`
			InterfaceName    string `json:"interface_name"`
			Stage            string `json:"stage"`
			Type             string `json:"type"`
			Severity         string `json:"severity"`
			Summary          string `json:"summary"`
			CountersJSON     string `json:"counters_json"`
			ByTypeJSON       string `json:"by_type_json"`
			RawRefJSON       string `json:"raw_ref_json"`
			DetailsJSON      string `json:"details_json"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		item := ingest.Diagnostic{
			SchemaVersion: row.SchemaVersion,
			DiagnosticID:  row.DiagnosticID,
			Timestamp:     row.Timestamp,
			SensorID:      row.SensorID,
			Collector:     ingest.Collector{Kind: row.CollectorKind, Version: row.CollectorVersion, Interface: row.InterfaceName},
			Stage:         row.Stage,
			Type:          row.Type,
			Severity:      row.Severity,
			Summary:       row.Summary,
			Counters:      map[string]int{},
			ByType:        map[string]int{},
			RawRef:        map[string]any{},
			Details:       map[string]any{},
		}
		_ = json.Unmarshal([]byte(row.CountersJSON), &item.Counters)
		_ = json.Unmarshal([]byte(row.ByTypeJSON), &item.ByType)
		_ = json.Unmarshal([]byte(row.RawRefJSON), &item.RawRef)
		_ = json.Unmarshal([]byte(row.DetailsJSON), &item.Details)
		items = append(items, item)
	}
	return items, scanner.Err()
}

func writeJSONLine(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

func chQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "\\'") + "'"
}

func clickHouseTimestamp(raw string) string {
	timestamp, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return raw
	}
	return timestamp.Format("2006-01-02 15:04:05.000000")
}

func jsonString(value any) string {
	if value == nil {
		return "{}"
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func stringFromMap(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	switch value := values[key].(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	default:
		return ""
	}
}

func uintFromMap(values map[string]any, key string) uint32 {
	if values == nil {
		return 0
	}
	switch value := values[key].(type) {
	case int:
		return uint32(value)
	case int64:
		return uint32(value)
	case float64:
		return uint32(value)
	case json.Number:
		parsed, _ := value.Int64()
		return uint32(parsed)
	default:
		return 0
	}
}
