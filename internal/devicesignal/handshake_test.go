package devicesignal

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// buildTCPFrame wraps payload in Ethernet/IPv4/TCP with the given source MAC, source IP and
// destination port. Only the fields the parser reads are meaningful.
func buildTCPFrame(srcMAC [6]byte, srcIP [4]byte, dstPort uint16, payload []byte) []byte {
	frame := make([]byte, 14+20+20+len(payload))
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], []byte{10, 0, 0, 1})
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 50000)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4
	copy(tcp[20:], payload)
	return frame
}

// clientHello builds a minimal TLS 1.2 ClientHello record with SNI and ALPN extensions.
func clientHello(sni, alpn string) []byte {
	var exts []byte
	name := []byte(sni)
	serverName := append([]byte{0, byte(len(name) + 3), 0, 0, byte(len(name))}, name...)
	exts = append(exts, 0, 0, byte(len(serverName)>>8), byte(len(serverName)))
	exts = append(exts, serverName...)
	if alpn != "" {
		proto := append([]byte{byte(len(alpn))}, []byte(alpn)...)
		list := append([]byte{byte(len(proto) >> 8), byte(len(proto))}, proto...)
		exts = append(exts, 0, 16, byte(len(list)>>8), byte(len(list)))
		exts = append(exts, list...)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id length
	body = append(body, 0, 2, 0x13, 0x01) // one cipher suite
	body = append(body, 1, 0)             // compression methods
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	handshake := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

func TestParseClientHelloExtractsSNIAndALPN(t *testing.T) {
	mac := [6]byte{0x02, 0, 0, 0, 0, 0x31}
	frame := buildTCPFrame(mac, [4]byte{10, 0, 0, 31}, 443, clientHello("Updates.Example.com", "h2"))
	got, ok := parseHandshakeFrame(frame)
	if !ok || got.SNI != "updates.example.com" || got.ALPN != "h2" || got.IP.String() != "10.0.0.31" {
		t.Fatalf("client hello not parsed: ok=%t got=%+v", ok, got)
	}
}

func TestParseHTTPRequestExtractsHostAndUserAgent(t *testing.T) {
	request := []byte("GET /index.html HTTP/1.1\r\nHost: Router.Local\r\nUser-Agent: UniFi-OS/2.1 (Linux)\r\nAccept: */*\r\n\r\n")
	frame := buildTCPFrame([6]byte{0x02, 0, 0, 0, 0, 0x32}, [4]byte{10, 0, 0, 32}, 80, request)
	got, ok := parseHandshakeFrame(frame)
	if !ok || got.Host != "router.local" || got.UserAgent != "UniFi-OS/2.1 (Linux)" {
		t.Fatalf("http request not parsed: ok=%t got=%+v", ok, got)
	}
}

func TestParseHandshakeIgnoresOtherTrafficAndResponses(t *testing.T) {
	mac := [6]byte{0x02, 0, 0, 0, 0, 0x33}
	cases := map[string][]byte{
		"tls on other port": buildTCPFrame(mac, [4]byte{10, 0, 0, 33}, 8443, clientHello("a.example", "")),
		"server response":   buildTCPFrame(mac, [4]byte{10, 0, 0, 33}, 443, []byte{0x16, 0x03, 0x03, 0, 1, 2}),
		"bulk data":         buildTCPFrame(mac, [4]byte{10, 0, 0, 33}, 443, []byte{0x17, 0x03, 0x03, 0, 5, 1, 2, 3, 4, 5}),
		"http response":     buildTCPFrame(mac, [4]byte{10, 0, 0, 33}, 80, []byte("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")),
	}
	for name, frame := range cases {
		if got, ok := parseHandshakeFrame(frame); ok {
			t.Fatalf("%s produced an observation: %+v", name, got)
		}
	}
}

func TestHandshakeSummaryBoundsDistinctValues(t *testing.T) {
	summary := &handshakeSummary{snis: map[string]bool{}, alpns: map[string]bool{}, hosts: map[string]bool{}, userAgents: map[string]bool{}}
	for i := 0; i < 20; i++ {
		summary.add(handshakeObservation{SNI: string(rune('a' + i))})
	}
	if summary.count != 20 || len(summary.snis) != maxHandshakeValues {
		t.Fatalf("summary not bounded: count=%d distinct=%d", summary.count, len(summary.snis))
	}
}

// The written summary must be a device event with a subject and an event ID, the shape the
// device-signals ingest requires, and it must carry the handshake fields as arrays.
func TestWriteHandshakeBucketEmitsIngestableDeviceEvent(t *testing.T) {
	path := t.TempDir() + "/handshake.jsonl"
	state := newCaptureBucket()
	state.handshakeEnabled = true
	mac := [6]byte{0x02, 0, 0, 0, 0, 0x34}
	state.addHandshake(buildTCPFrame(mac, [4]byte{10, 0, 0, 34}, 443, clientHello("api.example.net", "h2")))
	state.addHandshake(buildTCPFrame(mac, [4]byte{10, 0, 0, 34}, 80, []byte("GET / HTTP/1.1\r\nHost: r.local\r\nUser-Agent: ua-one\r\n\r\n")))
	if err := writeHandshakeBucket(path, "ncu-184-router-pilot", "bond0", "instance-1", nil, time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC), state.handshakes); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err = json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	payload := event["payload"].(map[string]any)
	if event["type"] != "device" || event["event_id"] == "" || event["subject"] == nil || payload["origin"] != "handshake" {
		t.Fatalf("event shape wrong: %v", event)
	}
	if got := payload["snis"].([]any); len(got) != 1 || got[0] != "api.example.net" {
		t.Fatalf("snis: %v", payload["snis"])
	}
	if got := payload["user_agents"].([]any); len(got) != 1 || got[0] != "ua-one" {
		t.Fatalf("user agents: %v", payload["user_agents"])
	}
}
