package devicesignal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
)

// handshakeObservation is what one client packet reveals about the device that sent it:
// a TLS ClientHello server name and ALPN, or an HTTP request's Host and User-Agent. Only
// the header fields are read; bodies and application data are never retained.
type handshakeObservation struct {
	FeaturesOmitted bool
	JA3             string
	EventID         string
	ObservedAt      time.Time
	Truncated       bool
	IP              netip.Addr
	MAC             [6]byte
	SNI             string
	ALPN            string
	Host            string
	UserAgent       string
}

// maxHandshakeValues bounds the distinct values kept per (device, bucket).
const maxHandshakeValues = 8

// parseHandshakeFrame extracts the handshake fields of an IPv4 TCP client packet to port
// 443 (TLS ClientHello) or 80 (HTTP request). It returns false for anything else.
func parseHandshakeFrame(frame []byte) (handshakeObservation, bool) {
	ethernet, ok := parseEthernetFrame(frame)
	if !ok || ethernet.etherType != 0x0800 {
		return handshakeObservation{}, false
	}
	ip := ethernet.payload
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return handshakeObservation{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+20 || ip[9] != 6 {
		return handshakeObservation{}, false
	}
	// Fragments after the first carry no TCP header.
	if binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return handshakeObservation{}, false
	}
	var source [4]byte
	copy(source[:], ip[12:16])
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total < ihl+20 || total > len(ip) {
		return handshakeObservation{}, false
	}
	tcp := ip[ihl:total]
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < 20 || len(tcp) <= dataOffset {
		return handshakeObservation{}, false
	}
	payload := tcp[dataOffset:]
	identity := append(append(append([]byte{}, ip[12:20]...), tcp[:8]...), payload...)
	sum := sha256.Sum256(identity)
	observation := handshakeObservation{IP: netip.AddrFrom4(source), MAC: ethernet.source, EventID: hex.EncodeToString(sum[:16]), ObservedAt: time.Now().UTC()}
	switch dstPort {
	case 443:
		sni, alpn, ok := parseClientHello(payload)
		if !ok && (len(payload) < 6 || payload[0] != 22 || payload[5] != 1) {
			return handshakeObservation{}, false
		}
		observation.JA3 = clientHelloJA3(payload)
		observation.Truncated = observation.JA3 == ""
		observation.SNI, observation.ALPN = sni, alpn
	case 80:
		host, userAgent, ok := parseHTTPRequestHeaders(payload)
		if !ok {
			return handshakeObservation{}, false
		}
		observation.Host, observation.UserAgent = host, userAgent
		observation.Truncated = !bytes.Contains(payload, []byte("\r\n\r\n"))
	default:
		return handshakeObservation{}, false
	}
	return observation, true
}

// parseClientHello reads server_name and the first ALPN protocol from a TLS ClientHello
// record. Extensions are walked in order and the walk stops at the end of the buffer, so a
// truncated record yields whatever was seen before the cut.
func parseClientHello(record []byte) (sni, alpn string, ok bool) {
	// record: type(1)=0x16 version(2) length(2) | handshake: type(1)=0x01 length(3) ...
	if len(record) < 9 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x01 {
		return "", "", false
	}
	body := record[9:]
	// client_version(2) random(32)
	if len(body) < 34 {
		return "", "", false
	}
	pos := 34
	if pos >= len(body) {
		return "", "", false
	}
	sessionLen := int(body[pos])
	pos += 1 + sessionLen
	if pos+2 > len(body) {
		return "", "", false
	}
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + cipherLen
	if pos+1 > len(body) {
		return "", "", false
	}
	compressionLen := int(body[pos])
	pos += 1 + compressionLen
	if pos+2 > len(body) {
		return "", "", false
	}
	extensionsEnd := pos + 2 + int(binary.BigEndian.Uint16(body[pos:pos+2]))
	if extensionsEnd > len(body) {
		extensionsEnd = len(body)
	}
	pos += 2
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		start := pos + 4
		end := start + extLen
		if end > extensionsEnd {
			end = extensionsEnd
		}
		data := body[start:end]
		switch extType {
		case 0: // server_name: list_length(2) type(1)=0 name_length(2) name
			if len(data) >= 5 && data[2] == 0 {
				nameLen := int(binary.BigEndian.Uint16(data[3:5]))
				if 5+nameLen <= len(data) {
					sni = strings.ToLower(string(data[5 : 5+nameLen]))
				}
			}
		case 16: // application_layer_protocol_negotiation: list_length(2) len(1) protocol
			if len(data) >= 4 && int(data[2]) <= len(data)-3 {
				alpn = string(data[3 : 3+int(data[2])])
			}
		}
		pos = start + extLen
	}
	return sni, alpn, sni != "" || alpn != ""
}

// parseHTTPRequestHeaders reads Host and User-Agent from an HTTP/1.x request head.
func parseHTTPRequestHeaders(payload []byte) (host, userAgent string, ok bool) {
	isRequest := false
	for _, method := range []string{"GET ", "POST ", "HEAD ", "PUT "} {
		if bytes.HasPrefix(payload, []byte(method)) {
			isRequest = true
			break
		}
	}
	if !isRequest {
		return "", "", false
	}
	head := payload
	if end := bytes.Index(head, []byte("\r\n\r\n")); end >= 0 {
		head = head[:end]
	}
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(string(name))) {
		case "host":
			host = strings.ToLower(strings.TrimSpace(string(value)))
		case "user-agent":
			userAgent = strings.TrimSpace(string(value))
		}
	}
	return host, userAgent, host != "" || userAgent != ""
}

// handshakeSummary accumulates the distinct handshake values seen for one device in one
// bucket. Emitting one summary per device keeps the event volume at the same order as the
// TTL events, which already pass through the same identity path.
type handshakeSummary struct {
	samples                        map[string]sharedaccess.HandshakeSample
	sampleCounts                   map[string]int
	overflow, truncated            int
	coverage                       sharedaccess.CoverageV2
	count                          int
	snis, alpns, hosts, userAgents map[string]bool
}

type handshakeKey struct {
	IP  netip.Addr
	MAC [6]byte
}

func newHandshakeSummary() *handshakeSummary {
	return &handshakeSummary{snis: map[string]bool{}, alpns: map[string]bool{}, hosts: map[string]bool{}, userAgents: map[string]bool{}}
}

func (s *handshakeSummary) add(o handshakeObservation) {
	s.count++
	if o.FeaturesOmitted {
		s.overflow++
	}
	if o.Truncated {
		s.truncated++
	}
	if s.samples == nil {
		s.samples = map[string]sharedaccess.HandshakeSample{}
		s.sampleCounts = map[string]int{}
	}
	if !o.Truncated && !o.FeaturesOmitted && o.EventID != "" && !o.ObservedAt.IsZero() {
		for family, value := range map[string]string{"user_agent": o.UserAgent, "ja3": o.JA3} {
			if value == "" {
				continue
			}
			key := family + "/" + o.EventID
			if _, ok := s.samples[key]; ok {
				continue
			}
			bucketKey := family + "/" + value + "/" + strconv.FormatInt(o.ObservedAt.Unix()/5, 10)
			if s.sampleCounts[bucketKey] >= 3 {
				continue
			}
			if len(s.samples) >= 288 {
				s.overflow++
				continue
			}
			s.sampleCounts[bucketKey]++
			s.samples[key] = sharedaccess.HandshakeSample{Family: family, Value: value, EventID: o.EventID, ObservedAt: o.ObservedAt, Bucket: o.ObservedAt.Unix() / 5}
		}
	}
	add := func(set map[string]bool, value string) {
		if value != "" {
			if !set[value] && len(set) >= maxHandshakeValues {
				s.overflow++
				return
			}
			set[value] = true
		}
	}
	add(s.snis, o.SNI)
	add(s.alpns, o.ALPN)
	add(s.hosts, o.Host)
	add(s.userAgents, o.UserAgent)
}

func sortedHandshakeValues(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// writeHandshakeBucket writes one device-signal event per device, in the same JSONL format
// as the TTL and router signals, so ingest reads it through the device-signals source.
func writeHandshakeBucket(path, sensorID, interfaceName, instance string, scope *normalized.CaptureScope, bucket time.Time, summaries map[handshakeKey]*handshakeSummary) error {
	if len(summaries) == 0 {
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	keys := selectHandshakeKeys(summaries, handshakeBucketLimit())
	encoder := json.NewEncoder(file)
	kept := map[handshakeKey]bool{}
	omitted := map[netip.Addr]int{}
	for _, key := range keys {
		kept[key] = true
	}
	for key := range summaries {
		if !kept[key] {
			omitted[key.IP]++
		}
	}
	for _, key := range keys {
		summary := summaries[key]
		mac := net.HardwareAddr(key.MAC[:]).String()
		identity := strings.Join([]string{sensorID, instance, key.IP.String(), mac, bucket.UTC().Format(time.RFC3339)}, "\x00")
		sum := sha256.Sum256([]byte("handshake\x00" + identity))
		samples := make([]sharedaccess.HandshakeSample, 0, len(summary.samples))
		for _, v := range summary.samples {
			samples = append(samples, v)
		}
		sort.Slice(samples, func(i, j int) bool {
			if !samples[i].ObservedAt.Equal(samples[j].ObservedAt) {
				return samples[i].ObservedAt.Before(samples[j].ObservedAt)
			}
			return samples[i].Family+samples[i].EventID < samples[j].Family+samples[j].EventID
		})
		coverage := summary.coverage
		coverage.Omitted = omitted[key.IP]
		coverage.Overflow += summary.overflow
		coverage.Truncated += summary.truncated
		event := normalized.Event{
			SchemaVersion: "v1", EventID: "device-" + hex.EncodeToString(sum[:16]),
			Source: "handshake-sidecar", SourceEventType: "handshake", Type: "device",
			Timestamp: bucket.UTC().Format(time.RFC3339Nano),
			Observer:  map[string]any{"sensor_id": sensorID, "interface": interfaceName, "collector_instance_id": instance},
			Subject:   map[string]any{"ip": key.IP.String(), "mac": mac},
			Flow:      map[string]any{"src_ip": key.IP.String(), "direction": "outbound", "ip_version": 4},
			Payload: map[string]any{
				"origin": "handshake", "mac": mac, "observed_count": summary.count,
				"handshake_schema": "handshake-samples/v1", "feature_samples": samples, "capture_coverage": coverage,
				"snis": sortedHandshakeValues(summary.snis), "alpns": sortedHandshakeValues(summary.alpns),
				"hosts": sortedHandshakeValues(summary.hosts), "user_agents": sortedHandshakeValues(summary.userAgents),
			},
			Confidence: 0.8,
		}
		event = scope.Apply(event)
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return file.Sync()
}

// defaultHandshakeBucketLimit bounds the device summaries written per bucket. Without a bound
// the summaries of every device that reached port 443 or 80 were written, which on 184 meant
// about 580k records per hour, four times the router TTL volume, on a disk already at 98%.
const defaultHandshakeBucketLimit = 200

// handshakeBucketLimit reads PROXY_SENTINEL_HANDSHAKE_BUCKET_LIMIT. Invalid or non-positive
// values fall back to the default so a typo cannot lift the bound.
func handshakeBucketLimit() int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_HANDSHAKE_BUCKET_LIMIT")))
	if err != nil || value <= 0 {
		return defaultHandshakeBucketLimit
	}
	return value
}

// selectHandshakeKeys keeps the most active devices of a bucket: highest observed_count
// first, then IP for a stable order. Devices outside the bound are dropped for this bucket
// only; the next bucket selects again, so a quiet device is never blocked for good.
func selectHandshakeKeys(summaries map[handshakeKey]*handshakeSummary, limit int) []handshakeKey {
	keys := make([]handshakeKey, 0, len(summaries))
	for key := range summaries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := summaries[keys[i]].count, summaries[keys[j]].count
		if a != b {
			return a > b
		}
		return keys[i].IP.Less(keys[j].IP)
	})
	if len(keys) > limit {
		keys = keys[:limit]
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].IP.Less(keys[j].IP) })
	return keys
}
