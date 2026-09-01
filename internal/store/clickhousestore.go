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

	"proxy-sentinel/internal/evidence"
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

func (s *ClickHouseStore) Health(ctx context.Context) error {
	return s.exec(ctx, "SELECT 1")
}

func (s *ClickHouseStore) WriteNormalizedEvents(ctx context.Context, events []normalized.Event) error {
	if len(events) == 0 {
		return nil
	}
	events = uniqueEventsByID(events)
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
			"account_id":        stringFromMap(event.Subject, "account_id"),
			"endpoint_id":       stringFromMap(event.Subject, "endpoint_id"),
			"campus_id":         firstNonEmpty(stringFromMap(event.Subject, "campus_id"), stringFromMap(event.Payload, "campus_id")),
			"department":        firstNonEmpty(stringFromMap(event.Subject, "department"), stringFromMap(event.Payload, "department")),
			"person_type":       firstNonEmpty(stringFromMap(event.Subject, "person_type"), stringFromMap(event.Payload, "person_type")),
			"building_id":       stringFromMap(event.Payload, "building_id"),
			"network_zone_id":   stringFromMap(event.Payload, "network_zone_id"),
			"ssid":              stringFromMap(event.Payload, "ssid"),
			"vlan":              stringFromMap(event.Payload, "vlan"),
			"ap":                stringFromMap(event.Payload, "ap"),
			"nas_ip":            stringFromMap(event.Payload, "nas_ip"),
			"auth_session_id":   stringFromMap(event.Payload, "session_id"),
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
	if limit < 0 {
		limit = defaultDPIEventLimit
	}
	cursor := query.Cursor
	if cursor < 0 {
		cursor = 0
	}
	where, err := eventWhereSQL(query)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`
SELECT timestamp, event_id, schema_version, source, source_event_type, type, subject_ip, observer_json, payload_json, flow_json, raw_ref_json, confidence
FROM normalized_events%s
ORDER BY timestamp DESC, event_id DESC
LIMIT %d OFFSET %d
FORMAT JSONEachRow`, where, limit, cursor)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return decodeEventRows(data)
}

// ListProxyReviewEvents reduces the seven-day TLS/QUIC/alert data set inside
// ClickHouse before returning it to the control plane. Returning raw rows can
// exceed the request deadline once the sensor has accumulated tens of millions
// of events.
func (s *ClickHouseStore) ListProxyReviewEvents(ctx context.Context, sensorID string, window time.Duration, limit int) ([]normalized.Event, error) {
	if limit <= 0 {
		limit = defaultProxyReviewLimit
	}
	intervalValue, intervalUnit := clickHouseInterval(window)
	clauses := []string{
		fmt.Sprintf("timestamp >= now() - INTERVAL %d %s", intervalValue, intervalUnit),
		"type IN ('tls', 'quic', 'alert')",
		"subject_ip != ''",
	}
	if sensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(sensorID))
	}
	sql := fmt.Sprintf(`
SELECT
  min(timestamp) AS first_seen,
  max(timestamp) AS last_seen,
  any(event_id) AS event_id,
  type,
  subject_ip,
  dst_ip,
  dst_port,
  proto,
  JSONExtractString(payload_json, 'sni') AS sni,
  JSONExtractString(payload_json, 'server_name') AS server_name,
  JSONExtractString(payload_json, 'host') AS host,
  JSONExtractString(payload_json, 'query') AS query,
  JSONExtractString(payload_json, 'ja3') AS ja3,
  JSONExtractString(payload_json, 'ja4') AS ja4,
  JSONExtractString(payload_json, 'signature') AS signature,
  JSONExtractString(payload_json, 'category') AS category,
  JSONExtractString(payload_json, 'action') AS action,
  JSONExtractInt(payload_json, 'severity') AS severity,
  JSONExtractRaw(payload_json, 'metadata') AS metadata_json,
  count() AS aggregate_count
FROM normalized_events
PREWHERE %s
GROUP BY type, subject_ip, dst_ip, dst_port, proto, sni, server_name, host, query, ja3, ja4, signature, category, action, severity, metadata_json
ORDER BY last_seen DESC
LIMIT %d
FORMAT JSONEachRow`, strings.Join(clauses, " AND "), limit)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	return decodeProxyReviewEventRows(data, sensorID)
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
	sampleLimit := activitySampleLimit(limit)
	events, err := s.ListEventSamples(ctx, Query{SrcIP: ip, Limit: sampleLimit})
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
	query.Window = window
	return s.GetActivityOverviewWithRisks(ctx, query, duration, map[string]risk.Snapshot{})
}

func (s *ClickHouseStore) GetDPIOverview(ctx context.Context, query ActivityQuery) (DPIOverview, error) {
	window, events, err := s.dpiEventSet(ctx, query)
	if err != nil {
		return DPIOverview{}, err
	}
	return BuildDPIOverview(query.SensorID, window, events, map[string]risk.Snapshot{}), nil
}

func (s *ClickHouseStore) ListDPITrends(ctx context.Context, query ActivityQuery) ([]DPITrendPoint, error) {
	return s.QueryDPITrends(ctx, query, map[string]risk.Snapshot{})
}

func (s *ClickHouseStore) ListDPIProtocolFlows(ctx context.Context, query ActivityQuery) ([]DPIProtocolFlow, error) {
	return s.QueryDPIProtocolFlows(ctx, query)
}

func (s *ClickHouseStore) ListDPIFingerprintConflicts(ctx context.Context, query ActivityQuery) ([]DPIFingerprintConflict, error) {
	return s.QueryDPIFingerprintConflicts(ctx, query, map[string]risk.Snapshot{})
}

func (s *ClickHouseStore) ListDPIFlows(ctx context.Context, query Query) (DPIFlowPage, error) {
	page, err := s.ListEvents(ctx, query)
	if err != nil {
		return DPIFlowPage{}, err
	}
	return DPIFlowPage{Items: BuildDPIFlowSamples(page.Items), Page: page.Page}, nil
}

func (s *ClickHouseStore) GetDPIFlow(ctx context.Context, flowID string) (DPIFlowDetail, bool, error) {
	event, ok, err := s.GetEvent(ctx, flowID)
	if err != nil || !ok {
		return DPIFlowDetail{}, ok, err
	}
	return BuildDPIFlowDetail(event, normalRisk(subjectIP(event)), []evidence.Evidence{}), true, nil
}

func (s *ClickHouseStore) ListIPDPIFlows(ctx context.Context, ip string, query Query) (DPIFlowPage, error) {
	query.SrcIP = ip
	return s.ListDPIFlows(ctx, query)
}

func (s *ClickHouseStore) dpiEventSet(ctx context.Context, query ActivityQuery) (string, []normalized.Event, error) {
	window, _, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return "", nil, err
	}
	limit := query.Limit
	if limit <= 0 {
		limit = defaultDPIEventLimit
	}
	events, err := s.ListEventSamples(ctx, Query{SensorID: query.SensorID, Window: window, Limit: limit})
	return window, events, err
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
	where, err := activityWhereSQL(query.SensorID, query.CampusID, query.AsOf, window)
	if err != nil {
		return ActivityOverview{}, err
	}
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
		RiskLevelCounts:    map[string]int{"normal": 0, "suspicious": 0, "high": 0, "confirmed": 0},
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
	if overview.TopActiveRiskIPs, overview.ActiveRiskIPCount, overview.RiskLevelCounts, err = s.activityRiskIPCounts(ctx, where, risks); err != nil {
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
SELECT concat(kind, ':', fingerprint_value) AS value, count() AS count, max(timestamp) AS last_seen
FROM (
  SELECT timestamp, 'ja3' AS kind, JSONExtractString(payload_json, 'ja3') AS fingerprint_value
  FROM normalized_events
  WHERE %s AND type = 'tls'
  UNION ALL
  SELECT timestamp, 'ja4' AS kind, JSONExtractString(payload_json, 'ja4') AS fingerprint_value
  FROM normalized_events
  WHERE %s AND type = 'tls'
)
WHERE fingerprint_value != ''
GROUP BY kind, fingerprint_value
ORDER BY count DESC, last_seen DESC, value ASC
LIMIT 20
FORMAT JSONEachRow`, where, where))
}

func (s *ClickHouseStore) activityRiskIPCounts(ctx context.Context, where string, risks map[string]risk.Snapshot) ([]ActivityIPSummary, int, map[string]int, error) {
	levelCounts := map[string]int{"normal": 0, "suspicious": 0, "high": 0, "confirmed": 0}
	riskIPs := make([]string, 0, len(risks))
	for ip, snapshot := range risks {
		if snapshot.Level != "" && snapshot.Level != "normal" {
			riskIPs = append(riskIPs, ip)
		}
	}
	sort.Strings(riskIPs)
	if len(riskIPs) == 0 {
		return []ActivityIPSummary{}, 0, levelCounts, nil
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
		return nil, 0, nil, err
	}
	counts, err := decodeActivityCountRows(data)
	if err != nil {
		return nil, 0, nil, err
	}
	items := make([]ActivityIPSummary, 0, len(counts))
	for _, count := range counts {
		snapshot := risks[count.Value]
		domains, err := s.activityDomainCounts(ctx, where, count.Value, 5)
		if err != nil {
			return nil, 0, nil, err
		}
		items = append(items, ActivityIPSummary{
			IP:         count.Value,
			EventCount: count.Count,
			RiskLevel:  snapshot.Level,
			Score:      snapshot.Score,
			TopDomains: domains,
			LastSeen:   count.LastSeen,
		})
		levelCounts[snapshot.Level]++
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
	return items, total, levelCounts, nil
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
		clauses = append(clauses, "(lower(event_id) LIKE "+like+" OR lower(subject_ip) LIKE "+like+" OR lower(dst_ip) LIKE "+like+" OR lower(source) LIKE "+like+" OR lower(source_event_type) LIKE "+like+" OR lower(type) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'query')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'host')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'sni')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'hostname')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'client_fqdn')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'vendor_class')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'mac')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'client_mac')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'device_hint')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'software_name')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'software_version')) LIKE "+like+")")
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
	if query.Fingerprint != "" {
		fingerprint, ok := normalizeFingerprintFilter(query.Fingerprint)
		if !ok {
			clauses = append(clauses, "0")
		} else {
			like := chQuote("%" + strings.ToLower(fingerprint) + "%")
			clauses = append(clauses, "(lower(JSONExtractString(payload_json, 'ja3')) LIKE "+like+" OR lower(JSONExtractString(payload_json, 'ja4')) LIKE "+like+")")
		}
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

func activityWhereSQL(sensorID, campusID, asOf string, duration time.Duration) (string, error) {
	intervalValue, intervalUnit := clickHouseInterval(duration)
	anchor := "now()"
	if strings.TrimSpace(asOf) != "" {
		parsed, err := time.Parse(time.RFC3339, asOf)
		if err != nil {
			return "", fmt.Errorf("invalid as_of: %w", err)
		}
		anchor = "parseDateTime64BestEffort(" + chQuote(parsed.UTC().Format(time.RFC3339Nano)) + ")"
	}
	clauses := []string{fmt.Sprintf("timestamp >= %s - INTERVAL %d %s", anchor, intervalValue, intervalUnit), "timestamp <= " + anchor}
	if sensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(sensorID))
	}
	if campusID != "" {
		clauses = append(clauses, "campus_id = "+chQuote(campusID))
	}
	return strings.Join(clauses, " AND "), nil
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
	seen := map[string]struct{}{}
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
		if event.EventID != "" {
			if _, ok := seen[event.EventID]; ok {
				continue
			}
			seen[event.EventID] = struct{}{}
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func decodeProxyReviewEventRows(data []byte, sensorID string) ([]normalized.Event, error) {
	events := []normalized.Event{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var row struct {
			FirstSeen      string `json:"first_seen"`
			LastSeen       string `json:"last_seen"`
			EventID        string `json:"event_id"`
			Type           string `json:"type"`
			SubjectIP      string `json:"subject_ip"`
			DstIP          string `json:"dst_ip"`
			DstPort        int    `json:"dst_port"`
			Proto          string `json:"proto"`
			SNI            string `json:"sni"`
			ServerName     string `json:"server_name"`
			Host           string `json:"host"`
			Query          string `json:"query"`
			JA3            string `json:"ja3"`
			JA4            string `json:"ja4"`
			Signature      string `json:"signature"`
			Category       string `json:"category"`
			Action         string `json:"action"`
			Severity       int    `json:"severity"`
			MetadataJSON   string `json:"metadata_json"`
			AggregateCount int    `json:"aggregate_count"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		payload := map[string]any{"_aggregate_count": row.AggregateCount}
		setMapString(payload, "sni", row.SNI)
		setMapString(payload, "server_name", row.ServerName)
		setMapString(payload, "host", row.Host)
		setMapString(payload, "query", row.Query)
		setMapString(payload, "ja3", row.JA3)
		setMapString(payload, "ja4", row.JA4)
		setMapString(payload, "signature", row.Signature)
		setMapString(payload, "category", row.Category)
		setMapString(payload, "action", row.Action)
		if row.Severity > 0 {
			payload["severity"] = row.Severity
		}
		if row.MetadataJSON != "" {
			var metadata any
			if json.Unmarshal([]byte(row.MetadataJSON), &metadata) == nil {
				payload["metadata"] = metadata
			}
		}
		flow := map[string]any{"start": normalizeClickHouseTimestamp(row.FirstSeen), "end": normalizeClickHouseTimestamp(row.LastSeen)}
		setMapString(flow, "dst_ip", row.DstIP)
		setMapString(flow, "proto", row.Proto)
		if row.DstPort > 0 {
			flow["dst_port"] = row.DstPort
		}
		events = append(events, normalized.Event{
			SchemaVersion: "v1", EventID: row.EventID, Timestamp: normalizeClickHouseTimestamp(row.LastSeen), Type: row.Type,
			Source: "clickhouse-aggregate", Subject: map[string]any{"ip": row.SubjectIP}, Observer: map[string]any{"sensor_id": sensorID},
			Payload: payload, Flow: flow, RawRef: map[string]any{"aggregate": true}, Confidence: 1,
		})
	}
	return events, scanner.Err()
}

func setMapString(target map[string]any, key, value string) {
	if strings.TrimSpace(value) != "" {
		target[key] = value
	}
}

func uniqueEventsByID(events []normalized.Event) []normalized.Event {
	if len(events) < 2 {
		return events
	}
	seen := map[string]struct{}{}
	unique := make([]normalized.Event, 0, len(events))
	for _, event := range events {
		if event.EventID != "" {
			if _, ok := seen[event.EventID]; ok {
				continue
			}
			seen[event.EventID] = struct{}{}
		}
		unique = append(unique, event)
	}
	return unique
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
