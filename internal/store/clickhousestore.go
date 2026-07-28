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
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
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
	page, err := s.ListEvents(ctx, query)
	if err != nil {
		return nil, err
	}
	return page.Items, nil
}

func (s *ClickHouseStore) ListEvents(ctx context.Context, query Query) (EventPage, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	where, err := eventWhereSQL(query)
	if err != nil {
		return EventPage{}, err
	}
	total, err := s.eventCount(ctx, where)
	if err != nil {
		return EventPage{}, err
	}
	sql := fmt.Sprintf(`
SELECT timestamp, event_id, schema_version, source, source_event_type, type, subject_ip, observer_json, payload_json, flow_json, raw_ref_json, confidence
FROM normalized_events%s
ORDER BY timestamp DESC, event_id DESC
LIMIT %d OFFSET %d
FORMAT JSONEachRow`, where, limit, query.Cursor)
	data, err := s.query(ctx, sql)
	if err != nil {
		return EventPage{}, err
	}
	events, err := decodeEventRows(data)
	if err != nil {
		return EventPage{}, err
	}
	var next *string
	if query.Cursor+len(events) < total {
		value := fmt.Sprintf("%d", query.Cursor+len(events))
		next = &value
	}
	return EventPage{Items: events, Page: Page{Limit: limit, NextCursor: next, Total: total}}, nil
}

func (s *ClickHouseStore) GetIPActivity(ctx context.Context, ip string, limit int) (ActivityProfile, error) {
	events, err := s.ListEventSamples(ctx, Query{Q: ip, Limit: defaultActivityEventLimit})
	if err != nil {
		return ActivityProfile{}, err
	}
	return BuildActivityProfile(ip, events, limit), nil
}

func (s *ClickHouseStore) GetActivityOverview(ctx context.Context, query ActivityQuery) (ActivityOverview, error) {
	window, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return ActivityOverview{}, err
	}
	return s.GetActivityOverviewWithRisks(ctx, ActivityQuery{SensorID: query.SensorID, Window: window, Limit: query.Limit}, duration, map[string]risk.Snapshot{})
}

func (s *ClickHouseStore) ListEventsForActivityOverview(ctx context.Context, sensorID string, window time.Duration, limit int) ([]normalized.Event, error) {
	if limit <= 0 {
		limit = defaultActivityOverviewEventLimit
	}
	intervalValue, intervalUnit := clickHouseInterval(window)
	clauses := []string{fmt.Sprintf("timestamp >= now() - INTERVAL %d %s", intervalValue, intervalUnit)}
	if sensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(sensorID))
	}
	sql := fmt.Sprintf(`
SELECT timestamp, event_id, schema_version, source, source_event_type, type, subject_ip, observer_json, payload_json, flow_json, raw_ref_json, confidence
FROM normalized_events
WHERE %s
ORDER BY timestamp DESC, event_id DESC
LIMIT %d
FORMAT JSONEachRow`, strings.Join(clauses, " AND "), limit)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return decodeEventRows(data)
}

func (s *ClickHouseStore) GetActivityOverviewWithRisks(ctx context.Context, query ActivityQuery, window time.Duration, risks map[string]risk.Snapshot) (ActivityOverview, error) {
	windowLabel := query.Window
	if windowLabel == "" {
		windowLabel = "1h"
	}
	where := activityWhereSQL(query.SensorID, window)
	overview := ActivityOverview{
		SensorID:           query.SensorID,
		Window:             windowLabel,
		EventTypeCounts:    []ActivityCount{},
		ProtocolCounts:     []ActivityCount{},
		TopDomains:         []ActivityCount{},
		TopHTTPHosts:       []ActivityCount{},
		TopTLSSNI:          []ActivityCount{},
		TopUserAgents:      []ActivityCount{},
		TopTLSFingerprints: []ActivityCount{},
		TopDstPorts:        []ActivityCount{},
		TopDstIPs:          []ActivityCount{},
		TopSourceIPs:       []ActivityCount{},
		TopActiveRiskIPs:   []ActivityIPSummary{},
	}

	summary, err := s.activitySummary(ctx, where)
	if err != nil {
		return ActivityOverview{}, err
	}
	overview.EventCount = summary.EventCount
	overview.ActiveIPCount = summary.ActiveIPCount
	overview.FirstSeen = summary.FirstSeen
	overview.LastSeen = summary.LastSeen
	overview.AccessObjectCount, err = s.activityAccessObjectCount(ctx, where)
	if err != nil {
		return ActivityOverview{}, err
	}

	if overview.EventTypeCounts, err = s.activityCounts(ctx, fmt.Sprintf(`
SELECT type AS value, count() AS count, max(timestamp) AS last_seen
FROM normalized_events
WHERE %s
GROUP BY type
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT 20
FORMAT JSONEachRow`, where)); err != nil {
		return ActivityOverview{}, err
	}
	if overview.ProtocolCounts, err = s.activityCounts(ctx, fmt.Sprintf(`
SELECT proto AS value, count() AS count, max(timestamp) AS last_seen
FROM normalized_events
WHERE %s AND proto != ''
GROUP BY proto
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT 20
FORMAT JSONEachRow`, where)); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopDstPorts, err = s.activityCounts(ctx, fmt.Sprintf(`
SELECT toString(dst_port) AS value, count() AS count, max(timestamp) AS last_seen
FROM normalized_events
WHERE %s AND dst_port > 0
GROUP BY dst_port
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT 20
FORMAT JSONEachRow`, where)); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopDstIPs, err = s.activityCounts(ctx, fmt.Sprintf(`
SELECT dst_ip AS value, count() AS count, max(timestamp) AS last_seen
FROM normalized_events
WHERE %s AND dst_ip != ''
GROUP BY dst_ip
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT 20
FORMAT JSONEachRow`, where)); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopSourceIPs, err = s.activityCounts(ctx, fmt.Sprintf(`
SELECT subject_ip AS value, count() AS count, max(timestamp) AS last_seen
FROM normalized_events
WHERE %s AND subject_ip != ''
GROUP BY subject_ip
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT 20
FORMAT JSONEachRow`, where)); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopDomains, err = s.activityDomainCounts(ctx, where, "", 20); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopHTTPHosts, err = s.activityPayloadCounts(ctx, where, "http", "host", "", 20); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopTLSSNI, err = s.activityPayloadCounts(ctx, where, "tls", "sni", "", 20); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopUserAgents, err = s.activityPayloadCounts(ctx, where, "http", "user_agent", "", 20); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopTLSFingerprints, err = s.activityTLSFingerprintCounts(ctx, where); err != nil {
		return ActivityOverview{}, err
	}
	if overview.TopActiveRiskIPs, overview.ActiveRiskIPCount, err = s.activityRiskIPCounts(ctx, where, risks); err != nil {
		return ActivityOverview{}, err
	}
	return overview, nil
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

type activitySummaryRow struct {
	EventCount    int
	ActiveIPCount int
	FirstSeen     string
	LastSeen      string
}

func (s *ClickHouseStore) activitySummary(ctx context.Context, where string) (activitySummaryRow, error) {
	data, err := s.query(ctx, fmt.Sprintf(`
SELECT count() AS event_count, uniqExact(subject_ip) AS active_ip_count, minOrNull(timestamp) AS first_seen, maxOrNull(timestamp) AS last_seen
FROM normalized_events
WHERE %s
FORMAT JSONEachRow`, where))
	if err != nil {
		return activitySummaryRow{}, err
	}
	var row struct {
		EventCount    int     `json:"event_count"`
		ActiveIPCount int     `json:"active_ip_count"`
		FirstSeen     *string `json:"first_seen"`
		LastSeen      *string `json:"last_seen"`
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	if scanner.Scan() {
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return activitySummaryRow{}, err
		}
	}
	result := activitySummaryRow{EventCount: row.EventCount, ActiveIPCount: row.ActiveIPCount}
	if row.FirstSeen != nil {
		result.FirstSeen = normalizeClickHouseTimestamp(*row.FirstSeen)
	}
	if row.LastSeen != nil {
		result.LastSeen = normalizeClickHouseTimestamp(*row.LastSeen)
	}
	return result, scanner.Err()
}

func (s *ClickHouseStore) activityAccessObjectCount(ctx context.Context, where string) (int, error) {
	data, err := s.query(ctx, fmt.Sprintf(`
SELECT uniqExact(value) AS count
FROM (
  SELECT multiIf(type = 'dns', JSONExtractString(payload_json, 'query'), type = 'http', JSONExtractString(payload_json, 'host'), type = 'tls', JSONExtractString(payload_json, 'sni'), '') AS value
  FROM normalized_events
  WHERE %s
)
WHERE value != ''
FORMAT JSONEachRow`, where))
	if err != nil {
		return 0, err
	}
	return decodeSingleCount(data)
}

func (s *ClickHouseStore) activityCounts(ctx context.Context, sql string) ([]ActivityCount, error) {
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return decodeActivityCountRows(data)
}

func (s *ClickHouseStore) activityDomainCounts(ctx context.Context, where string, subjectIP string, limit int) ([]ActivityCount, error) {
	subjectClause := ""
	if subjectIP != "" {
		subjectClause = " AND subject_ip = " + chQuote(subjectIP)
	}
	return s.activityCounts(ctx, fmt.Sprintf(`
SELECT value, count() AS count, max(timestamp) AS last_seen
FROM (
  SELECT timestamp, multiIf(type = 'dns', JSONExtractString(payload_json, 'query'), type = 'http', JSONExtractString(payload_json, 'host'), type = 'tls', JSONExtractString(payload_json, 'sni'), '') AS value
  FROM normalized_events
  WHERE %s%s
)
WHERE value != ''
GROUP BY value
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT %d
FORMAT JSONEachRow`, where, subjectClause, limit))
}

func (s *ClickHouseStore) activityPayloadCounts(ctx context.Context, where string, eventType string, field string, prefix string, limit int) ([]ActivityCount, error) {
	return s.activityCounts(ctx, fmt.Sprintf(`
SELECT concat(%s, JSONExtractString(payload_json, %s)) AS value, count() AS count, max(timestamp) AS last_seen
FROM normalized_events
WHERE %s AND type = %s AND JSONExtractString(payload_json, %s) != ''
GROUP BY value
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT %d
FORMAT JSONEachRow`, chQuote(prefix), chQuote(field), where, chQuote(eventType), chQuote(field), limit))
}

func (s *ClickHouseStore) activityTLSFingerprintCounts(ctx context.Context, where string) ([]ActivityCount, error) {
	return s.activityCounts(ctx, fmt.Sprintf(`
SELECT concat(kind, ':', value) AS value, count() AS count, max(timestamp) AS last_seen
FROM (
  SELECT timestamp, 'ja3' AS kind, JSONExtractString(payload_json, 'ja3') AS value
  FROM normalized_events
  WHERE %s AND type = 'tls'
  UNION ALL
  SELECT timestamp, 'ja4' AS kind, JSONExtractString(payload_json, 'ja4') AS value
  FROM normalized_events
  WHERE %s AND type = 'tls'
)
WHERE value != ''
GROUP BY kind, value
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT 20
FORMAT JSONEachRow`, where, where))
}

func (s *ClickHouseStore) activityRiskIPCounts(ctx context.Context, where string, risks map[string]risk.Snapshot) ([]ActivityIPSummary, int, error) {
	riskIPs := make([]string, 0, len(risks))
	for ip, snapshot := range risks {
		if snapshot.Level != "" && snapshot.Level != "normal" {
			riskIPs = append(riskIPs, ip)
		}
	}
	sort.Strings(riskIPs)
	if len(riskIPs) == 0 {
		return []ActivityIPSummary{}, 0, nil
	}
	quotedIPs := make([]string, 0, len(riskIPs))
	for _, ip := range riskIPs {
		quotedIPs = append(quotedIPs, chQuote(ip))
	}
	data, err := s.query(ctx, fmt.Sprintf(`
SELECT subject_ip AS value, count() AS count, max(timestamp) AS last_seen
FROM normalized_events
WHERE %s AND subject_ip IN (%s)
GROUP BY subject_ip
ORDER BY count DESC, last_seen DESC, value ASC
FORMAT JSONEachRow`, where, strings.Join(quotedIPs, ",")))
	if err != nil {
		return nil, 0, err
	}
	counts, err := decodeActivityCountRows(data)
	if err != nil {
		return nil, 0, err
	}
	items := make([]ActivityIPSummary, 0, len(counts))
	for _, count := range counts {
		snapshot := risks[count.Value]
		domains, err := s.activityDomainCounts(ctx, where, count.Value, 5)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, ActivityIPSummary{
			IP:         count.Value,
			EventCount: count.Count,
			RiskLevel:  snapshot.Level,
			Score:      snapshot.Score,
			TopDomains: domains,
			LastSeen:   count.LastSeen,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		leftRank, _ := levelRank(items[i].RiskLevel)
		rightRank, _ := levelRank(items[j].RiskLevel)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		if items[i].EventCount != items[j].EventCount {
			return items[i].EventCount > items[j].EventCount
		}
		return items[i].IP < items[j].IP
	})
	total := len(items)
	if len(items) > 50 {
		items = items[:50]
	}
	return items, total, nil
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

func (s *ClickHouseStore) eventCount(ctx context.Context, where string) (int, error) {
	data, err := s.query(ctx, fmt.Sprintf(`
SELECT count() AS count
FROM normalized_events%s
FORMAT JSONEachRow`, where))
	if err != nil {
		return 0, err
	}
	return decodeSingleCount(data)
}

func eventWhereSQL(query Query) (string, error) {
	clauses := []string{}
	if query.Q != "" {
		like := chQuote("%" + strings.ToLower(query.Q) + "%")
		clauses = append(clauses, "(lower(event_id) LIKE "+like+" OR lower(subject_ip) LIKE "+like+" OR lower(dst_ip) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'query')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'host')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'sni')) LIKE "+like+")")
	}
	if query.Level != "" {
		clauses = append(clauses, "type = "+chQuote(query.Level))
	}
	if query.SensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(query.SensorID))
	}
	if query.From != "" {
		if _, err := optionalTime(query.From); err != nil {
			return "", fmt.Errorf("bad from: %w", err)
		}
		clauses = append(clauses, "timestamp >= parseDateTime64BestEffort("+chQuote(query.From)+")")
	}
	if query.To != "" {
		if _, err := optionalTime(query.To); err != nil {
			return "", fmt.Errorf("bad to: %w", err)
		}
		clauses = append(clauses, "timestamp <= parseDateTime64BestEffort("+chQuote(query.To)+")")
	}
	if query.Window != "" && query.From == "" && query.To == "" {
		_, duration, err := NormalizeActivityWindow(query.Window)
		if err != nil {
			return "", err
		}
		intervalValue, intervalUnit := clickHouseInterval(duration)
		clauses = append(clauses, fmt.Sprintf("timestamp >= now() - INTERVAL %d %s", intervalValue, intervalUnit))
	}
	if query.SrcIP != "" {
		clauses = append(clauses, "(subject_ip = "+chQuote(query.SrcIP)+" OR src_ip = "+chQuote(query.SrcIP)+")")
	}
	if query.DstIP != "" {
		clauses = append(clauses, "dst_ip = "+chQuote(query.DstIP))
	}
	if query.Domain != "" {
		like := chQuote("%" + strings.ToLower(query.Domain) + "%")
		clauses = append(clauses, "(lower(JSONExtractString(payload_json, 'query')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'host')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'sni')) LIKE "+like+")")
	}
	if query.UserAgent != "" {
		like := chQuote("%" + strings.ToLower(query.UserAgent) + "%")
		clauses = append(clauses, "lower(JSONExtractString(payload_json, 'user_agent')) LIKE "+like)
	}
	if query.Port > 0 {
		clauses = append(clauses, fmt.Sprintf("dst_port = %d", query.Port))
	}
	if query.Proto != "" {
		clauses = append(clauses, "proto = "+chQuote(strings.ToLower(query.Proto)))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), nil
}

func activityWhereSQL(sensorID string, duration time.Duration) string {
	intervalValue, intervalUnit := clickHouseInterval(duration)
	clauses := []string{fmt.Sprintf("timestamp >= now() - INTERVAL %d %s", intervalValue, intervalUnit)}
	if sensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(sensorID))
	}
	return strings.Join(clauses, " AND ")
}

func decodeSingleCount(data []byte) (int, error) {
	var row struct {
		Count int `json:"count"`
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	if scanner.Scan() {
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return 0, err
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return row.Count, nil
}

func decodeActivityCountRows(data []byte) ([]ActivityCount, error) {
	items := []ActivityCount{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var row struct {
			Value    string `json:"value"`
			Count    int    `json:"count"`
			LastSeen string `json:"last_seen"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		if row.Value == "" {
			continue
		}
		items = append(items, ActivityCount{Value: row.Value, Count: row.Count, LastSeen: normalizeClickHouseTimestamp(row.LastSeen)})
	}
	return items, scanner.Err()
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
			Timestamp:       normalizeClickHouseTimestamp(row.Timestamp),
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
			Timestamp:     normalizeClickHouseTimestamp(row.Timestamp),
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

func normalizeClickHouseTimestamp(raw string) string {
	for _, layout := range []string{"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05"} {
		timestamp, err := time.ParseInLocation(layout, raw, time.FixedZone("Asia/Shanghai", 8*60*60))
		if err == nil {
			return timestamp.Format(time.RFC3339Nano)
		}
	}
	return raw
}

func clickHouseInterval(duration time.Duration) (int, string) {
	if duration%time.Hour == 0 {
		return int(duration / time.Hour), "HOUR"
	}
	return int(duration / time.Minute), "MINUTE"
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
