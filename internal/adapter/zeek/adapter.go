package zeek

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

type Options struct {
	SensorID string
}

type Stats struct {
	Read      int            `json:"read"`
	Emitted   int            `json:"emitted"`
	Skipped   int            `json:"skipped"`
	Malformed int            `json:"malformed"`
	ByType    map[string]int `json:"by_type"`
}

type logParser struct {
	fields     []string
	separator  string
	unsetField string
	emptyField string
}

func Convert(r io.Reader, w io.Writer, opts Options) (Stats, error) {
	stats := Stats{ByType: map[string]int{}}
	parser := logParser{separator: "\t", unsetField: "-", emptyField: "(empty)"}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	for scanner.Scan() {
		stats.Read++
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" {
			stats.Skipped++
			continue
		}
		if strings.HasPrefix(line, "#") {
			parser.updateDirective(line)
			stats.Skipped++
			continue
		}

		event, err := parser.convertLine([]byte(rawLine), stats.Read, opts)
		if err != nil {
			if _, ok := err.(malformedLineError); ok {
				stats.Malformed++
			} else {
				stats.Skipped++
			}
			continue
		}
		if err := encoder.Encode(event); err != nil {
			return stats, fmt.Errorf("write normalized event: %w", err)
		}
		stats.Emitted++
		stats.ByType[event.Type]++
	}
	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("read zeek input: %w", err)
	}
	return stats, nil
}

func ConvertFiles(inputPath, outputPath string, opts Options) (Stats, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return Stats{}, err
	}
	defer closeInput()

	output, closeOutput, err := openOutput(outputPath)
	if err != nil {
		return Stats{}, err
	}
	defer closeOutput()

	return Convert(input, output, opts)
}

type malformedLineError struct {
	err error
}

func (e malformedLineError) Error() string {
	return e.err.Error()
}

func (p *logParser) updateDirective(line string) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	key := parts[0]
	value := strings.TrimSpace(strings.TrimPrefix(line, key))
	switch key {
	case "#separator":
		p.separator = zeekEscaped(value)
	case "#unset_field":
		p.unsetField = value
	case "#empty_field":
		p.emptyField = value
	case "#fields":
		p.fields = strings.Fields(value)
	}
}

func (p logParser) convertLine(raw []byte, lineOffset int, opts Options) (normalized.Event, error) {
	fields, err := p.fieldsFor(raw)
	if err != nil {
		return normalized.Event{}, err
	}
	if isSoftwareFields(fields) {
		return softwareEventFromFields(raw, fields, lineOffset, opts)
	}
	return dhcpEventFromFields(raw, fields, lineOffset, opts)
}

func (p logParser) fieldsFor(raw []byte) (map[string]string, error) {
	line := strings.TrimSpace(string(raw))
	if strings.HasPrefix(line, "{") {
		var values map[string]any
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, malformedLineError{err: err}
		}
		fields := map[string]string{}
		for key, value := range values {
			fields[key] = stringify(value)
		}
		return fields, nil
	}

	if len(p.fields) == 0 {
		return nil, fmt.Errorf("missing zeek #fields directive")
	}
	parts := strings.Split(line, p.separator)
	if len(parts) != len(p.fields) {
		return nil, malformedLineError{err: fmt.Errorf("expected %d zeek fields, got %d", len(p.fields), len(parts))}
	}
	fields := make(map[string]string, len(parts))
	for index, key := range p.fields {
		value := parts[index]
		if value == p.unsetField || value == p.emptyField {
			value = ""
		}
		fields[key] = value
	}
	return fields, nil
}

func isSoftwareFields(fields map[string]string) bool {
	return first(fields, "software_type") != "" && first(fields, "name") != "" && first(fields, "host") != ""
}

func dhcpEventFromFields(raw []byte, fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	timestamp := normalizeTimestamp(first(fields, "ts", "timestamp"))
	if timestamp == "" {
		return normalized.Event{}, fmt.Errorf("missing zeek ts")
	}

	subjectIP := first(fields, "assigned_addr", "requested_addr", "client_addr")
	if subjectIP == "" || subjectIP == "0.0.0.0" {
		return normalized.Event{}, fmt.Errorf("missing DHCP client address")
	}

	clientIP := first(fields, "client_addr", "requested_addr", "assigned_addr")
	if clientIP == "" {
		clientIP = "0.0.0.0"
	}
	serverIP := first(fields, "server_addr")
	if serverIP == "" {
		serverIP = "255.255.255.255"
	}

	payload := dhcpPayload(fields)
	subject := map[string]any{"ip": subjectIP}
	if mac := first(fields, "mac", "client_mac", "client_chaddr"); mac != "" {
		subject["mac"] = normalizeMAC(mac)
	}

	observer := map[string]any{}
	if opts.SensorID != "" {
		observer["sensor_id"] = opts.SensorID
	}

	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID(raw, lineOffset),
		Source:          "zeek",
		SourceEventType: "dhcp",
		Type:            "device",
		Timestamp:       timestamp,
		Observer:        observer,
		Subject:         subject,
		Flow: map[string]any{
			"src_ip":    clientIP,
			"dst_ip":    serverIP,
			"src_port":  68,
			"dst_port":  67,
			"proto":     "udp",
			"direction": "outbound",
		},
		Payload:    payload,
		Confidence: 0.9,
		RawRef: map[string]any{
			"backend":     "zeek",
			"log":         "dhcp",
			"line_offset": lineOffset,
		},
	}, nil
}

func softwareEventFromFields(raw []byte, fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	timestamp := normalizeTimestamp(first(fields, "ts", "timestamp"))
	if timestamp == "" {
		return normalized.Event{}, fmt.Errorf("missing zeek ts")
	}
	subjectIP := first(fields, "host")
	if subjectIP == "" || subjectIP == "0.0.0.0" {
		return normalized.Event{}, fmt.Errorf("missing Zeek software host")
	}
	observer := map[string]any{}
	if opts.SensorID != "" {
		observer["sensor_id"] = opts.SensorID
	}
	hostPort := intField(fields, "host_p")
	flow := map[string]any{
		"src_ip":    subjectIP,
		"direction": "outbound",
	}
	if hostPort > 0 {
		flow["src_port"] = hostPort
	}
	payload := softwarePayload(fields)
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID(raw, lineOffset),
		Source:          "zeek",
		SourceEventType: "software",
		Type:            "device",
		Timestamp:       timestamp,
		Observer:        observer,
		Subject:         map[string]any{"ip": subjectIP},
		Flow:            flow,
		Payload:         payload,
		Confidence:      0.78,
		RawRef: map[string]any{
			"backend":     "zeek",
			"log":         "software",
			"line_offset": lineOffset,
		},
	}, nil
}

func dhcpPayload(fields map[string]string) map[string]any {
	payload := map[string]any{"origin": "dhcp"}
	copyPayload(payload, fields, "host_name", "hostname")
	copyPayload(payload, fields, "hostname", "hostname")
	copyPayload(payload, fields, "client_software", "vendor_class")
	copyPayload(payload, fields, "vendor_class", "vendor_class")
	copyPayload(payload, fields, "requested_options", "requested_options")
	copyMACPayload(payload, fields, "mac")
	copyMACPayload(payload, fields, "client_mac")
	copyPayload(payload, fields, "client_chaddr", "client_chaddr")
	copyPayload(payload, fields, "client_fqdn", "client_fqdn")
	copyPayload(payload, fields, "domain", "domain")
	copyPayload(payload, fields, "requested_addr", "requested_addr")
	copyPayload(payload, fields, "assigned_addr", "assigned_addr")
	copyPayload(payload, fields, "msg_types", "msg_types")
	copyPayload(payload, fields, "uids", "uids")

	if hint := deviceHint(payload); hint != "" {
		payload["device_hint"] = hint
	}
	return payload
}

func softwarePayload(fields map[string]string) map[string]any {
	payload := map[string]any{"origin": "software"}
	copyPayload(payload, fields, "software_type", "software_type")
	copyPayload(payload, fields, "name", "software_name")
	copyPayload(payload, fields, "unparsed_version", "software_version")
	copyPayload(payload, fields, "unparsed_version", "software_unparsed_version")
	if payload["software_version"] == nil {
		version := versionString(fields)
		if version != "" {
			payload["software_version"] = version
		}
	}
	if strings.EqualFold(first(fields, "software_type"), "DHCP::CLIENT") {
		if version := first(fields, "unparsed_version"); version != "" {
			payload["vendor_class"] = version
		} else if name := first(fields, "name"); name != "" {
			payload["vendor_class"] = name
		}
	}
	if hint := softwareDeviceHint(payload); hint != "" {
		payload["device_hint"] = hint
	}
	return payload
}

func versionString(fields map[string]string) string {
	parts := []string{}
	for _, key := range []string{"version.major", "version.minor", "version.minor2", "version.minor3"} {
		value := strings.TrimSpace(fields[key])
		if value == "" || value == "-" {
			continue
		}
		parts = append(parts, value)
	}
	if len(parts) == 0 {
		return ""
	}
	version := strings.Join(parts, ".")
	if addl := strings.TrimSpace(fields["version.addl"]); addl != "" && addl != "-" {
		version += " " + addl
	}
	return version
}

func softwareDeviceHint(payload map[string]any) string {
	text := strings.ToLower(strings.Join([]string{
		stringField(payload, "software_type"),
		stringField(payload, "software_name"),
		stringField(payload, "software_version"),
		stringField(payload, "vendor_class"),
	}, " "))
	switch {
	case strings.Contains(text, "msft"), strings.Contains(text, "microsoft"), strings.Contains(text, "windows"):
		return "windows"
	case strings.Contains(text, "android"):
		return "android"
	case strings.Contains(text, "apple"), strings.Contains(text, "iphone"), strings.Contains(text, "ipad"), strings.Contains(text, "mac"):
		return "apple"
	case strings.Contains(text, "udhcp"), strings.Contains(text, "dhcpcd"), strings.Contains(text, "linux"):
		return "linux"
	default:
		return ""
	}
}

func copyMACPayload(payload map[string]any, fields map[string]string, sourceKey string) {
	value := normalizeMAC(fields[sourceKey])
	if value == "" {
		return
	}
	if _, exists := payload["client_mac"]; !exists {
		payload["client_mac"] = value
	}
	if _, exists := payload["mac"]; !exists {
		payload["mac"] = value
	}
}

func copyPayload(payload map[string]any, fields map[string]string, sourceKey, targetKey string) {
	value := strings.TrimSpace(fields[sourceKey])
	if value == "" {
		return
	}
	if _, exists := payload[targetKey]; exists {
		return
	}
	payload[targetKey] = value
}

func deviceHint(payload map[string]any) string {
	text := strings.ToLower(strings.Join([]string{
		stringField(payload, "hostname"),
		stringField(payload, "vendor_class"),
		stringField(payload, "client_fqdn"),
	}, " "))
	switch {
	case strings.Contains(text, "iphone"), strings.Contains(text, "ipad"), strings.Contains(text, "ios"), strings.Contains(text, "apple"), strings.Contains(text, "macbook"), strings.Contains(text, "imac"):
		return "apple"
	case strings.Contains(text, "android"):
		return "android"
	case strings.Contains(text, "windows"), strings.Contains(text, "microsoft"), strings.Contains(text, "msft"):
		return "windows"
	case strings.Contains(text, "chromebook"), strings.Contains(text, "chromeos"):
		return "chromeos"
	case strings.Contains(text, "linux"), strings.Contains(text, "dhcpcd"), strings.Contains(text, "ubuntu"), strings.Contains(text, "debian"):
		return "linux"
	default:
		return ""
	}
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func first(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[key]); value != "" {
			return value
		}
	}
	return ""
}

func intField(fields map[string]string, key string) int {
	value := strings.TrimSpace(fields[key])
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ToLower(strings.ReplaceAll(value, "-", ":"))
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return value
	}
	for i, part := range parts {
		if len(part) == 1 {
			parts[i] = "0" + part
		}
	}
	return strings.Join(parts, ":")
}

func stringify(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, stringify(item))
		}
		return strings.Join(values, ",")
	default:
		return fmt.Sprint(typed)
	}
}

func zeekEscaped(value string) string {
	switch value {
	case `\x09`:
		return "\t"
	case `\x20`:
		return " "
	default:
		return value
	}
}

func normalizeTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if seconds, err := strconv.ParseFloat(value, 64); err == nil {
		sec := int64(seconds)
		nsec := int64((seconds - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}

func eventID(raw []byte, lineOffset int) string {
	sum := sha256.Sum256(append(raw, []byte(fmt.Sprintf("|%d", lineOffset))...))
	return "zeek-" + hex.EncodeToString(sum[:])[:24]
}

func openInput(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	return file, file.Close, nil
}

func openOutput(path string) (io.Writer, func() error, error) {
	if path == "-" || path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output: %w", err)
	}
	return file, file.Close, nil
}
