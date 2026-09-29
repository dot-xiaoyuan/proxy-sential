package identity

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

type Options struct {
	SensorID string
	Source   string
}

type Stats struct {
	Read      int            `json:"read"`
	Emitted   int            `json:"emitted"`
	Skipped   int            `json:"skipped"`
	Malformed int            `json:"malformed"`
	ByType    map[string]int `json:"by_type"`
}

func Convert(r io.Reader, w io.Writer, opts Options) (Stats, error) {
	stats := Stats{ByType: map[string]int{}}
	data, err := io.ReadAll(r)
	if err != nil {
		return stats, fmt.Errorf("read identity input: %w", err)
	}
	records, err := parseRecords(data)
	if err != nil {
		stats.Malformed++
		return stats, err
	}
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	for index, fields := range records {
		stats.Read++
		event, err := convertRecord(fields, index+1, opts)
		if err != nil {
			stats.Skipped++
			continue
		}
		if err := encoder.Encode(event); err != nil {
			return stats, fmt.Errorf("write normalized identity event: %w", err)
		}
		stats.Emitted++
		stats.ByType[event.Type]++
	}
	return stats, nil
}

func parseRecords(data []byte) ([]map[string]string, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return []map[string]string{}, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		return parseJSONL(strings.NewReader(trimmed))
	}
	return parseCSV(strings.NewReader(trimmed))
}

func parseJSONL(r io.Reader) ([]map[string]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	records := []map[string]string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("parse identity jsonl: %w", err)
		}
		record := map[string]string{}
		for key, value := range raw {
			record[key] = stringify(value)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan identity jsonl: %w", err)
	}
	return records, nil
}

func parseCSV(r io.Reader) ([]map[string]string, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse identity csv: %w", err)
	}
	if len(rows) == 0 {
		return []map[string]string{}, nil
	}
	headers := rows[0]
	records := make([]map[string]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		record := map[string]string{}
		for index, header := range headers {
			if index < len(row) {
				record[strings.TrimSpace(header)] = strings.TrimSpace(row[index])
			}
		}
		records = append(records, record)
	}
	return records, nil
}

func convertRecord(fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	timestamp := normalizeTimestamp(first(fields, "timestamp", "ts", "event_time", "login_time", "start_time"))
	if timestamp == "" {
		return normalized.Event{}, fmt.Errorf("missing identity timestamp")
	}
	ip := first(fields, "ip", "client_ip", "assigned_ip", "framed_ip_address", "src_ip")
	accountID := first(fields, "account_id", "user_id", "username", "user_name", "calling_user")
	mac := normalizeMAC(first(fields, "mac", "client_mac", "calling_station_id", "calling_station", "endpoint_mac"))
	endpointID := first(fields, "endpoint_id", "device_id")
	if endpointID == "" && mac != "" {
		endpointID = "mac:" + mac
	}
	accessID := first(fields, "access_id", "ap", "ap_name", "switch_port", "port", "nas_port_id")
	entityRole := first(fields, "entity_role", "role")
	if entityRole == "" {
		if mac != "" || endpointID != "" {
			entityRole = "endpoint"
		} else {
			entityRole = "unknown"
		}
	}
	conf := floatField(first(fields, "identity_confidence", "confidence"), defaultConfidence(entityRole))
	if ip == "" && accountID == "" && mac == "" && endpointID == "" {
		return normalized.Event{}, fmt.Errorf("identity record has no subject")
	}
	if ip == "" {
		ip = "0.0.0.0"
	}

	source := opts.Source
	if source == "" {
		source = first(fields, "source", "origin")
	}
	if source == "" {
		source = "identity"
	}

	subject := map[string]any{
		"ip":                  ip,
		"entity_role":         entityRole,
		"identity_confidence": conf,
	}
	if accountID != "" {
		subject["account_id"] = accountID
		subject["user_id"] = accountID
	}
	if endpointID != "" {
		subject["endpoint_id"] = endpointID
	}
	if mac != "" {
		subject["mac"] = mac
	}
	if accessID != "" {
		subject["access_id"] = accessID
	}
	for _, key := range []string{"person_type", "department", "campus_id", "building_id"} {
		if value := first(fields, key); value != "" {
			subject[key] = value
		}
	}

	payload := map[string]any{
		"origin": source,
	}
	for _, key := range []string{"group_id", "product_id", "access_domain", "heartbeat_interval_seconds", "reconcile_interval_seconds", "device_class"} {
		copyPayload(payload, fields, key, key)
	}
	copyPayload(payload, fields, "action", "action")
	copyPayload(payload, fields, "auth_method", "auth_method")
	copyPayload(payload, fields, "vlan", "vlan")
	copyPayload(payload, fields, "ap", "ap")
	copyPayload(payload, fields, "ap_name", "ap")
	copyPayload(payload, fields, "switch_id", "switch_id")
	copyPayload(payload, fields, "switch_port", "switch_port")
	copyPayload(payload, fields, "nas_ip", "nas_ip")
	copyPayload(payload, fields, "nas_port_id", "nas_port_id")
	copyPayload(payload, fields, "session_id", "session_id")
	copyPayload(payload, fields, "source_session_id", "source_session_id")
	copyPayload(payload, fields, "source_instance_id", "source_instance_id")
	for _, key := range []string{"raw_online_id", "source_login_generation", "session_id_source"} {
		copyPayload(payload, fields, key, key)
	}
	copyPayload(payload, fields, "auth_mac", "auth_mac")
	copyPayload(payload, fields, "observed_mac", "observed_mac")
	for _, key := range []string{"person_type", "department", "campus_id", "building_id", "network_zone_id", "ssid", "session_status", "access_type"} {
		copyPayload(payload, fields, key, key)
	}

	observer := map[string]any{}
	if opts.SensorID != "" {
		observer["sensor_id"] = opts.SensorID
	}
	raw := canonical(fields)
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         "identity-" + shortHash(canonical(map[string]string{"source": source, "sensor_id": opts.SensorID, "record": raw})),
		Source:          source,
		SourceEventType: "identity",
		Type:            "identity",
		Timestamp:       timestamp,
		Observer:        observer,
		Subject:         subject,
		Flow: map[string]any{
			"src_ip":    ip,
			"dst_ip":    firstDefault(fields, "0.0.0.0", "server_ip", "nas_ip", "dst_ip"),
			"proto":     "other",
			"direction": "unknown",
		},
		Payload:    payload,
		Confidence: conf,
		RawRef: map[string]any{
			"backend":     source,
			"line_offset": lineOffset,
		},
	}, nil
}

func first(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[key]); value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func firstDefault(fields map[string]string, fallback string, keys ...string) string {
	if value := first(fields, keys...); value != "" {
		return value
	}
	return fallback
}

func copyPayload(payload map[string]any, fields map[string]string, sourceKey, targetKey string) {
	if value := first(fields, sourceKey); value != "" {
		payload[targetKey] = value
	}
}

func normalizeTimestamp(value string) string {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999-0700",
		"2006-01-02T15:04:05.999999-0700",
		"2006-01-02T15:04:05-0700",
	} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.Format(time.RFC3339Nano)
		}
	}
	return value
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, "-", ":")
	value = strings.ReplaceAll(value, ".", "")
	if len(value) == 12 && !strings.Contains(value, ":") {
		parts := []string{}
		for i := 0; i < 12; i += 2 {
			parts = append(parts, value[i:i+2])
		}
		value = strings.Join(parts, ":")
	}
	return value
}

func floatField(value string, fallback float64) float64 {
	if value == "" {
		return fallback
	}
	var parsed float64
	if _, err := fmt.Sscanf(value, "%f", &parsed); err != nil {
		return fallback
	}
	if parsed < 0 {
		return 0
	}
	if parsed > 1 {
		return 1
	}
	return parsed
}

func defaultConfidence(role string) float64 {
	if role == "endpoint" {
		return 0.92
	}
	if role == "unknown" {
		return 0.45
	}
	return 0.85
}

func stringify(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		data, _ := json.Marshal(typed)
		return string(data)
	}
}

func canonical(fields map[string]string) string {
	data, _ := json.Marshal(fields)
	return string(data)
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:20]
}
