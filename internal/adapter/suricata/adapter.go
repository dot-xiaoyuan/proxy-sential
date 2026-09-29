package suricata

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
)

type Options struct {
	CaptureScope        *normalized.CaptureScope
	ProxyProducer       *proxyprotocol.Producer
	SensorID            string
	CollectorInstanceID string
}

type Stats struct {
	Read      int            `json:"read"`
	Emitted   int            `json:"emitted"`
	Skipped   int            `json:"skipped"`
	Malformed int            `json:"malformed"`
	ByType    map[string]int `json:"by_type"`
}

type eveEvent struct {
	Timestamp string         `json:"timestamp"`
	FlowID    json.Number    `json:"flow_id"`
	InIface   string         `json:"in_iface"`
	EventType string         `json:"event_type"`
	SrcIP     string         `json:"src_ip"`
	DestIP    string         `json:"dest_ip"`
	SrcPort   *int           `json:"src_port"`
	DestPort  *int           `json:"dest_port"`
	Proto     string         `json:"proto"`
	AppProto  string         `json:"app_proto"`
	TxID      any            `json:"tx_id"`
	Flow      map[string]any `json:"flow"`
	DNS       map[string]any `json:"dns"`
	TLS       map[string]any `json:"tls"`
	HTTP      map[string]any `json:"http"`
	QUIC      map[string]any `json:"quic"`
	Alert     map[string]any `json:"alert"`
	Ether     map[string]any `json:"ether"`
	VLAN      any            `json:"vlan"`
}

var supportedTypes = map[string]bool{
	"flow":  true,
	"dns":   true,
	"tls":   true,
	"http":  true,
	"quic":  true,
	"alert": true,
}

func Convert(r io.Reader, w io.Writer, opts Options) (Stats, error) {
	stats := Stats{ByType: map[string]int{}}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	for scanner.Scan() {
		stats.Read++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			stats.Skipped++
			continue
		}

		event, err := convertLine([]byte(line), stats.Read, opts)
		if err != nil {
			if _, ok := err.(malformedLineError); ok {
				stats.Malformed++
			} else {
				stats.Skipped++
			}
			continue
		}

		event = opts.CaptureScope.Apply(event)
		if err := encoder.Encode(event); err != nil {
			return stats, fmt.Errorf("write normalized event: %w", err)
		}
		stats.Emitted++
		stats.ByType[event.Type]++
		if proxy, ok := proxyTransaction(event, opts); ok {
			if err := encoder.Encode(proxy); err != nil {
				return stats, err
			}
			stats.Emitted++
			stats.ByType[proxy.Type]++
		}
	}
	if err := scanner.Err(); err != nil {
		return stats, fmt.Errorf("read eve input: %w", err)
	}

	return stats, nil
}

type malformedLineError struct {
	err error
}

func (e malformedLineError) Error() string {
	return e.err.Error()
}

func convertLine(raw []byte, lineOffset int, opts Options) (normalized.Event, error) {
	var eve eveEvent
	if err := json.Unmarshal(raw, &eve); err != nil {
		return normalized.Event{}, malformedLineError{err: err}
	}
	if !supportedTypes[eve.EventType] {
		return normalized.Event{}, fmt.Errorf("unsupported event_type %q", eve.EventType)
	}
	if eve.SrcIP == "" || eve.DestIP == "" || eve.Timestamp == "" {
		return normalized.Event{}, fmt.Errorf("missing required eve fields")
	}

	flow := map[string]any{
		"src_ip":    eve.SrcIP,
		"dst_ip":    eve.DestIP,
		"proto":     normalizeProto(eve.Proto),
		"direction": direction(eve.SrcIP, eve.DestIP),
	}
	if appProtocol := strings.TrimSpace(eve.AppProto); appProtocol != "" {
		flow["app_protocol"] = strings.ToLower(appProtocol)
	}
	if id := normalized.ConnectionID(opts.SensorID, "suricata", opts.CollectorInstanceID, string(eve.FlowID)); id != "" {
		flow["connection_id"] = id
	}
	if eve.SrcPort != nil {
		flow["src_port"] = *eve.SrcPort
	}
	if eve.DestPort != nil {
		flow["dst_port"] = *eve.DestPort
	}
	copyNumeric(flow, eve.Flow, "bytes_toserver")
	copyNumeric(flow, eve.Flow, "bytes_toclient")
	copyNumeric(flow, eve.Flow, "pkts_toserver")
	copyNumeric(flow, eve.Flow, "pkts_toclient")
	copyString(flow, eve.Flow, "start")
	copyString(flow, eve.Flow, "end")

	payload := payloadFor(eve)
	if vlan := firstVLAN(eve.VLAN); vlan != "" {
		payload["vlan"] = vlan
	}
	observer := map[string]any{"collector_instance_id": opts.CollectorInstanceID}
	if opts.SensorID != "" {
		observer["sensor_id"] = opts.SensorID
	}
	if eve.InIface != "" {
		observer["interface"] = eve.InIface
	}

	rawRef := map[string]any{
		"backend":     "suricata",
		"line_offset": lineOffset,
	}
	if eve.FlowID != "" {
		rawRef["flow_id"] = eve.FlowID
	}
	if eve.TxID != nil {
		rawRef["tx_id"] = eve.TxID
	}

	subject := map[string]any{
		"ip":          subjectIP(eve.SrcIP, eve.DestIP),
		"entity_role": "unknown",
	}
	if mac := subjectMAC(eve); mac != "" {
		subject["mac"] = mac
	}
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID(raw, lineOffset),
		Source:          "suricata",
		SourceEventType: eve.EventType,
		Type:            eve.EventType,
		Timestamp:       normalizeTimestamp(eve.Timestamp),
		Observer:        observer,
		Subject:         subject,
		Flow:            flow,
		Payload:         payload,
		Confidence:      1.0,
		RawRef:          rawRef,
	}, nil
}

func payloadFor(e eveEvent) map[string]any {
	switch e.EventType {
	case "dns":
		return dnsPayload(e.DNS)
	case "tls":
		return tlsPayload(e.TLS)
	case "http":
		return httpPayload(e.HTTP)
	case "quic":
		return quicPayload(e.QUIC)
	case "alert":
		return alertPayload(e.Alert)
	case "flow":
		payload := map[string]any{}
		copyString(payload, e.Flow, "state")
		copyString(payload, e.Flow, "reason")
		copyBool(payload, e.Flow, "alerted")
		return payload
	default:
		return map[string]any{}
	}
}

func quicPayload(quic map[string]any) map[string]any {
	payload := map[string]any{}
	copyString(payload, quic, "sni")
	copyString(payload, quic, "version")
	copyString(payload, quic, "ja3")
	copyString(payload, quic, "ja4")
	copyString(payload, quic, "alpn")
	copyString(payload, quic, "cyu")
	copyString(payload, quic, "cyb")
	copyString(payload, quic, "server_name")
	if payload["sni"] == nil {
		copyStringAs(payload, quic, "server_name", "sni")
	}
	return payload
}

func alertPayload(alert map[string]any) map[string]any {
	payload := map[string]any{}
	copyNumeric(payload, alert, "signature_id")
	copyNumeric(payload, alert, "gid")
	copyNumeric(payload, alert, "rev")
	copyNumeric(payload, alert, "severity")
	copyString(payload, alert, "signature")
	copyString(payload, alert, "category")
	copyString(payload, alert, "action")
	if metadata, ok := alert["metadata"]; ok {
		payload["metadata"] = metadata
	}
	return payload
}

func dnsPayload(dns map[string]any) map[string]any {
	payload := map[string]any{}
	copyStringAs(payload, dns, "rrname", "query")
	copyStringAs(payload, dns, "rrtype", "qtype")
	copyString(payload, dns, "rcode")
	if answers, ok := dns["answers"].([]any); ok {
		values := make([]string, 0, len(answers))
		for _, answer := range answers {
			item, ok := answer.(map[string]any)
			if !ok {
				continue
			}
			if rdata, ok := item["rdata"].(string); ok && rdata != "" {
				values = append(values, rdata)
			}
		}
		if len(values) > 0 {
			payload["answers"] = values
		}
	}
	copyStringAs(payload, dns, "type", "dns_type")
	return payload
}

func tlsPayload(tls map[string]any) map[string]any {
	payload := map[string]any{}
	copyString(payload, tls, "sni")
	copyString(payload, tls, "version")
	if ja3 := fingerprint(tls["ja3"]); ja3 != "" {
		payload["ja3"] = ja3
	}
	if ja4 := fingerprint(tls["ja4"]); ja4 != "" {
		payload["ja4"] = ja4
	}
	if alpn, ok := tls["alpn"].([]any); ok {
		values := make([]string, 0, len(alpn))
		for _, item := range alpn {
			if value, ok := item.(string); ok && value != "" {
				values = append(values, value)
			}
		}
		if len(values) > 0 {
			payload["alpn"] = values
		}
	}
	copyStringAs(payload, tls, "subject", "certificate_subject")
	copyStringAs(payload, tls, "issuerdn", "certificate_issuer")
	copyStringAs(payload, tls, "issuer", "certificate_issuer")
	copyStringAs(payload, tls, "serial", "certificate_serial")
	copyStringAs(payload, tls, "fingerprint", "certificate_fingerprint")
	for _, key := range []string{"san", "subjectaltname"} {
		if value, ok := tls[key]; ok {
			payload["certificate_san"] = value
		}
	}
	if certificates, ok := tls["certificates"].([]any); ok && len(certificates) > 0 {
		if certificate, ok := certificates[0].(map[string]any); ok {
			copyStringAs(payload, certificate, "subject", "certificate_subject")
			copyStringAs(payload, certificate, "issuer", "certificate_issuer")
			if san, ok := certificate["san"]; ok {
				payload["certificate_san"] = san
			}
		}
	}
	return payload
}

func httpPayload(http map[string]any) map[string]any {
	payload := map[string]any{}
	copyStringAs(payload, http, "hostname", "host")
	copyStringAs(payload, http, "http_method", "method")
	copyString(payload, http, "url")
	copyStringAs(payload, http, "http_user_agent", "user_agent")
	copyStringAs(payload, http, "http_server", "server")
	copyString(payload, http, "server")
	copyStringAs(payload, http, "http_title", "title")
	copyString(payload, http, "title")
	copyString(payload, http, "protocol")
	copyNumeric(payload, http, "status")
	copyNumeric(payload, http, "length")
	return payload
}

func subjectMAC(event eveEvent) string {
	subject := subjectIP(event.SrcIP, event.DestIP)
	key := "src_mac"
	if subject == event.DestIP {
		key = "dest_mac"
	}
	value, _ := event.Ether[key].(string)
	return normalizeMAC(value)
}

func normalizeMAC(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ":"))
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return ""
	}
	for index, part := range parts {
		if len(part) == 1 {
			parts[index] = "0" + part
		}
		if len(parts[index]) != 2 {
			return ""
		}
	}
	return strings.Join(parts, ":")
}

func firstVLAN(value any) string {
	switch item := value.(type) {
	case string:
		return strings.TrimSpace(item)
	case json.Number:
		return item.String()
	case float64:
		return fmt.Sprintf("%.0f", item)
	case []any:
		if len(item) > 0 {
			return firstVLAN(item[0])
		}
	}
	return ""
}

func fingerprint(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]any:
		for _, key := range []string{"hash", "value"} {
			if value, ok := typed[key].(string); ok {
				return value
			}
		}
	}
	return ""
}

func normalizeProto(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	case "icmp", "ipv6-icmp":
		return "icmp"
	default:
		return "other"
	}
}

func subjectIP(srcIP, dstIP string) string {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)
	switch {
	case srcPrivate && !dstPrivate:
		return srcIP
	case dstPrivate && !srcPrivate:
		return dstIP
	default:
		return srcIP
	}
}

func direction(srcIP, dstIP string) string {
	srcPrivate := isPrivateIP(srcIP)
	dstPrivate := isPrivateIP(dstIP)
	switch {
	case srcPrivate && !dstPrivate:
		return "outbound"
	case dstPrivate && !srcPrivate:
		return "inbound"
	default:
		return "unknown"
	}
}

func isPrivateIP(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.IsPrivate()
}

func normalizeTimestamp(value string) string {
	for _, layout := range []string{
		time.RFC3339Nano,
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

func eventID(raw []byte, lineOffset int) string {
	sum := sha256.Sum256(raw)
	// Keep IDs stable when the same record is replayed from another batch.
	return "suricata-" + hex.EncodeToString(sum[:])[:24]
}

func copyString(dst map[string]any, src map[string]any, key string) {
	copyStringAs(dst, src, key, key)
}

func copyStringAs(dst map[string]any, src map[string]any, srcKey, dstKey string) {
	if value, ok := src[srcKey].(string); ok && value != "" {
		dst[dstKey] = value
	}
}

func copyNumeric(dst map[string]any, src map[string]any, key string) {
	value, ok := src[key]
	if !ok {
		return
	}
	switch typed := value.(type) {
	case float64:
		dst[key] = int64(typed)
	case int:
		dst[key] = typed
	case int64:
		dst[key] = typed
	}
}

func copyBool(dst map[string]any, src map[string]any, key string) {
	if value, ok := src[key].(bool); ok {
		dst[key] = value
	}
}
