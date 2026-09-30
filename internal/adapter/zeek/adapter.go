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

	"proxy-sentinel/internal/devicename"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
)

type Options struct {
	CaptureScope        *normalized.CaptureScope
	CollectorInstanceID string
	ProxyProducer       *proxyprotocol.Producer
	SensorID            string
	LogKind             string
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
		if opts.CollectorInstanceID != "" {
			if event.Observer == nil {
				event.Observer = map[string]any{}
			}
			event.Observer["collector_instance_id"] = opts.CollectorInstanceID
		}
		event = opts.CaptureScope.Apply(event)
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
	if opts.LogKind == "proxy" {
		return proxyEvent(raw, fields, opts)
	}
	switch opts.LogKind {
	case "conn":
		return connectionEventFromFields(raw, fields, lineOffset, opts)
	case "dns", "http", "ssl", "tls", "x509":
		return protocolEventFromFields(raw, fields, lineOffset, opts)
	case "lldp", "ssdp":
		return infrastructureDiscoveryEventFromFields(raw, fields, lineOffset, opts)
	}
	if isSoftwareFields(fields) {
		return softwareEventFromFields(raw, fields, lineOffset, opts)
	}
	if opts.LogKind == "mdns" || opts.LogKind == "nbns" || opts.LogKind == "llmnr" || opts.LogKind == "ttl" {
		return discoveryEventFromFields(raw, fields, lineOffset, opts)
	}
	return dhcpEventFromFields(raw, fields, lineOffset, opts)
}

func connectionEventFromFields(raw []byte, fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	timestamp := normalizeTimestamp(first(fields, "ts", "timestamp"))
	srcIP, dstIP := first(fields, "id.orig_h", "src_ip"), first(fields, "id.resp_h", "dst_ip")
	if timestamp == "" || srcIP == "" || dstIP == "" {
		return normalized.Event{}, fmt.Errorf("missing Zeek conn fields")
	}
	flow := zeekFlow(fields, srcIP, dstIP)
	for _, pair := range [][2]string{{"orig_bytes", "bytes_toserver"}, {"resp_bytes", "bytes_toclient"}, {"orig_pkts", "pkts_toserver"}, {"resp_pkts", "pkts_toclient"}} {
		if value := intField(fields, pair[0]); value > 0 {
			flow[pair[1]] = value
		}
	}
	payload := map[string]any{}
	copyPayload(payload, fields, "service", "service")
	copyPayload(payload, fields, "conn_state", "state")
	copyPayload(payload, fields, "history", "history")
	copyPayload(payload, fields, "vlan", "vlan")
	return zeekNetworkEvent(raw, fields, lineOffset, opts, "flow", "conn", timestamp, srcIP, dstIP, flow, payload), nil
}

func protocolEventFromFields(raw []byte, fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	timestamp := normalizeTimestamp(first(fields, "ts", "timestamp"))
	srcIP, dstIP := first(fields, "id.orig_h", "src_ip", "host"), first(fields, "id.resp_h", "dst_ip")
	if timestamp == "" || srcIP == "" {
		return normalized.Event{}, fmt.Errorf("missing Zeek %s fields", opts.LogKind)
	}
	if dstIP == "" {
		dstIP = srcIP
	}
	kind := opts.LogKind
	eventType := kind
	if kind == "ssl" || kind == "x509" {
		eventType = "tls"
	}
	payload := map[string]any{}
	switch kind {
	case "dns":
		copyPayload(payload, fields, "query", "query")
		copyPayload(payload, fields, "answers", "answers")
		copyPayload(payload, fields, "qtype_name", "qtype")
		copyPayload(payload, fields, "rcode_name", "rcode")
	case "http":
		for _, pair := range [][2]string{{"host", "host"}, {"method", "method"}, {"uri", "url"}, {"user_agent", "user_agent"}, {"server", "server"}, {"title", "title"}, {"status_code", "status"}} {
			copyPayload(payload, fields, pair[0], pair[1])
		}
	case "ssl", "tls", "x509":
		for _, pair := range [][2]string{{"server_name", "sni"}, {"version", "version"}, {"cipher", "cipher"}, {"subject", "certificate_subject"}, {"certificate.subject", "certificate_subject"}, {"issuer", "certificate_issuer"}, {"certificate.issuer", "certificate_issuer"}, {"san.dns", "certificate_san"}, {"san", "certificate_san"}, {"ja3", "ja3"}, {"ja4", "ja4"}} {
			copyPayload(payload, fields, pair[0], pair[1])
		}
	}
	copyPayload(payload, fields, "vlan", "vlan")
	return zeekNetworkEvent(raw, fields, lineOffset, opts, eventType, kind, timestamp, srcIP, dstIP, zeekFlow(fields, srcIP, dstIP), payload), nil
}

func infrastructureDiscoveryEventFromFields(raw []byte, fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	timestamp := normalizeTimestamp(first(fields, "ts", "timestamp"))
	srcIP := first(fields, "id.orig_h", "src_ip", "host", "address", "ip")
	if timestamp == "" || srcIP == "" {
		return normalized.Event{}, fmt.Errorf("missing Zeek %s fields", opts.LogKind)
	}
	dstIP := first(fields, "id.resp_h", "dst_ip")
	if dstIP == "" {
		if opts.LogKind == "ssdp" {
			dstIP = "239.255.255.250"
		} else {
			dstIP = srcIP
		}
	}
	payload := map[string]any{"origin": opts.LogKind}
	if opts.LogKind == "lldp" {
		for _, pair := range [][2]string{{"system_name", "system_name"}, {"system_description", "system_description"}, {"system_capabilities", "system_capabilities"}, {"capabilities", "capabilities"}, {"chassis_id", "chassis_id"}, {"port_id", "port_id"}, {"management_address", "management_address"}} {
			copyPayload(payload, fields, pair[0], pair[1])
		}
		normalizePayloadName(payload, "system_name")
	} else {
		for _, pair := range [][2]string{{"st", "st"}, {"nt", "nt"}, {"usn", "usn"}, {"server", "server"}, {"location", "location"}} {
			copyPayload(payload, fields, pair[0], pair[1])
		}
	}
	copyPayload(payload, fields, "vlan", "vlan")
	subject := map[string]any{"ip": srcIP, "entity_role": "network_device"}
	if mac := first(fields, "src_mac", "mac", "chassis_id"); mac != "" {
		subject["mac"] = normalizeMAC(mac)
	}
	event := zeekNetworkEvent(raw, fields, lineOffset, opts, "discovery", opts.LogKind, timestamp, srcIP, dstIP, zeekFlow(fields, srcIP, dstIP), payload)
	event.Subject = subject
	event.Confidence = 0.85
	return event, nil
}

func zeekNetworkEvent(raw []byte, fields map[string]string, lineOffset int, opts Options, eventType, sourceType, timestamp, srcIP, dstIP string, flow, payload map[string]any) normalized.Event {
	observer := map[string]any{}
	if opts.SensorID != "" {
		observer["sensor_id"] = opts.SensorID
	}
	subject := map[string]any{"ip": srcIP}
	if mac := first(fields, "orig_l2_addr", "src_mac", "mac", "client_mac"); mac != "" {
		subject["mac"] = normalizeMAC(mac)
	}
	return normalized.Event{SchemaVersion: "v1", EventID: eventID(raw, lineOffset), Source: "zeek", SourceEventType: sourceType, Type: eventType, Timestamp: timestamp, Observer: observer, Subject: subject, Flow: flow, Payload: payload, Confidence: 0.9, RawRef: map[string]any{"backend": "zeek", "log": sourceType, "line_offset": lineOffset}}
}

func zeekFlow(fields map[string]string, srcIP, dstIP string) map[string]any {
	proto := strings.ToLower(first(fields, "proto"))
	if proto != "tcp" && proto != "udp" && proto != "icmp" {
		proto = "other"
	}
	flow := map[string]any{"src_ip": srcIP, "dst_ip": dstIP, "proto": proto, "direction": "unknown"}
	if port := intField(fields, "id.orig_p"); port > 0 {
		flow["src_port"] = port
	}
	if port := intField(fields, "id.resp_p"); port > 0 {
		flow["dst_port"] = port
	}
	if uid := first(fields, "uid"); uid != "" {
		flow["connection_id"] = uid
	}
	return flow
}

func discoveryEventFromFields(raw []byte, fields map[string]string, lineOffset int, opts Options) (normalized.Event, error) {
	timestamp := normalizeTimestamp(first(fields, "ts", "timestamp"))
	if timestamp == "" {
		return normalized.Event{}, fmt.Errorf("missing zeek ts")
	}
	subjectIP := first(fields, "src_ip", "client_addr", "id.orig_h", "host", "address", "ip")
	if subjectIP == "" {
		return normalized.Event{}, fmt.Errorf("missing %s subject address", opts.LogKind)
	}
	destination := first(fields, "dst_ip", "id.resp_h", "server_addr")
	if destination == "" {
		destination = "224.0.0.252"
		if opts.LogKind == "mdns" {
			destination = "224.0.0.251"
		}
	}
	payload := map[string]any{"origin": opts.LogKind}
	if opts.LogKind == "mdns" {
		payload["is_response"] = first(fields, "is_response") == "true" || first(fields, "is_response") == "T"
		for _, key := range []string{"record_type", "record_name", "record_address", "record_ttl", "service_target", "record_text", "parser_version"} {
			if value := first(fields, key); value != "" {
				payload[key] = value
			}
		}
	}
	for _, mapping := range [][2]string{{"hostname", "hostname"}, {"name", "device_name"}, {"query", "query"}, {"answers", "answers"}, {"mac", "client_mac"}, {"client_mac", "client_mac"}, {"ttl", "ttl"}} {
		if value := first(fields, mapping[0]); value != "" {
			if opts.LogKind == "mdns" && (mapping[1] == "device_name" || mapping[1] == "hostname") {
				setNormalizedPayloadName(payload, "discovery_name", value)
				continue
			}
			if mapping[1] == "ttl" {
				if number, err := strconv.Atoi(value); err == nil {
					payload[mapping[1]] = number
				}
			} else {
				payload[mapping[1]] = value
			}
		}
	}
	subject := map[string]any{"ip": subjectIP}
	if mac := first(fields, "mac", "client_mac"); mac != "" {
		subject["mac"] = normalizeMAC(mac)
	}
	observer := map[string]any{}
	if opts.SensorID != "" {
		observer["sensor_id"] = opts.SensorID
	}
	proto := first(fields, "proto")
	if proto == "" {
		proto = "udp"
	}
	direction := first(fields, "direction")
	if direction == "" {
		direction = "outbound"
	}
	return normalized.Event{SchemaVersion: "v1", EventID: eventID(raw, lineOffset), Source: "zeek", SourceEventType: opts.LogKind, Type: "device", Timestamp: timestamp, Observer: observer, Subject: subject, Flow: map[string]any{"src_ip": subjectIP, "dst_ip": destination, "proto": strings.ToLower(proto), "direction": direction}, Payload: payload, Confidence: 0.75, RawRef: map[string]any{"backend": "zeek", "log": opts.LogKind, "line_offset": lineOffset}}, nil
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
	copyPayload(payload, fields, "lease_time", "lease_time")
	if at := normalizeTimestamp(first(fields, "lease_observed_at")); at != "" {
		payload["lease_observed_at"] = at
	}
	copyNormalizedPayloadName(payload, fields, "host_name", "hostname")
	copyNormalizedPayloadName(payload, fields, "hostname", "hostname")
	copyPayload(payload, fields, "client_software", "vendor_class")
	copyPayload(payload, fields, "vendor_class", "vendor_class")
	copyPayload(payload, fields, "requested_options", "requested_options")
	copyMACPayload(payload, fields, "mac")
	copyMACPayload(payload, fields, "client_mac")
	copyPayload(payload, fields, "client_chaddr", "client_chaddr")
	copyNormalizedPayloadName(payload, fields, "client_fqdn", "client_fqdn")
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

func copyNormalizedPayloadName(payload map[string]any, fields map[string]string, field, key string) {
	if value := first(fields, field); value != "" {
		setNormalizedPayloadName(payload, key, value)
	}
}

func normalizePayloadName(payload map[string]any, key string) {
	value, _ := payload[key].(string)
	if value != "" {
		setNormalizedPayloadName(payload, key, value)
	}
}

func setNormalizedPayloadName(payload map[string]any, key, value string) {
	normalized, encoding := devicename.Normalize(value)
	if normalized == "" {
		delete(payload, key)
		return
	}
	payload[key] = normalized
	if normalized != strings.TrimSpace(value) {
		payload[key+"_original"] = value
		payload[key+"_encoding"] = encoding
	}
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
	// Zeek timestamps and connection fields are part of the raw record. The
	// current line number is deliberately excluded so replay stays idempotent.
	sum := sha256.Sum256(raw)
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
