package devicesignal

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestParseFrameIPv4AndVLAN(t *testing.T) {
	ethernet := []byte{0, 1, 2, 3, 4, 5, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x81, 0x00, 0, 7, 0x08, 0x00}
	ipv4 := make([]byte, 20)
	ipv4[0], ipv4[8] = 0x45, 63
	copy(ipv4[12:16], []byte{10, 1, 2, 3})
	value, ok := parseFrame(append(ethernet, ipv4...))
	if !ok || value.IP != "10.1.2.3" || value.TTL != 63 || value.Version != 4 || value.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected observation: %+v ok=%t", value, ok)
	}
}

func TestParseFrameIPv6HopLimit(t *testing.T) {
	frame := make([]byte, 14+40)
	copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1})
	frame[12], frame[13], frame[14], frame[21] = 0x86, 0xdd, 0x60, 126
	copy(frame[22:38], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8})
	value, ok := parseFrame(frame)
	if !ok || value.IP != "fd00::8" || value.TTL != 126 || value.Version != 6 {
		t.Fatalf("unexpected observation: %+v ok=%t", value, ok)
	}
}

func TestParseTCPFingerprintFromIPv4SYN(t *testing.T) {
	frame := make([]byte, 14+20+40)
	copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	frame[12], frame[13] = 0x08, 0x00
	ipv4 := frame[14:34]
	ipv4[0], ipv4[6], ipv4[8], ipv4[9] = 0x45, 0x40, 63, 6
	copy(ipv4[12:16], []byte{172, 20, 1, 2})
	copy(ipv4[16:20], []byte{203, 0, 113, 10})
	tcp := frame[34:]
	tcp[12], tcp[13] = 0xa0, 0x02
	copy(tcp[20:], []byte{
		2, 4, 0x05, 0xb4,
		4, 2,
		8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		1,
		3, 3, 7,
	})

	value, ok := parsePacketFrame(frame)
	if !ok {
		t.Fatal("expected IPv4 SYN observation")
	}
	want := "mss=1460,ws=7,sack=true,ts=true,df=true,opt=2-4-8-1-3"
	if got := value.TCP.String(); got != want {
		t.Fatalf("unexpected TCP fingerprint: got %q want %q", got, want)
	}
}

func TestWritePacketBucketIncludesTCPStack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	value := tcpFingerprint{MSS: 1460, WindowScale: 7, Flags: 1 | 2 | 4 | 8, OptionCount: 3}
	value.Options[0], value.Options[1], value.Options[2] = 2, 4, 3
	key := packetBucketKey{IP: netip.MustParseAddr("172.20.1.2"), Direction: "outbound", Version: 4, TTL: 63, TCP: value}
	if err := writePacketBucketWithScope(path, "sensor", "eth0", "instance", nil, time.Now().UTC().Truncate(time.Second), map[packetBucketKey]int{key: 2}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event normalized.Event
	if err = json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	if got := event.Payload["tcp_stack"]; got != "mss=1460,ws=7,sack=true,ts=true,df=true,opt=2-4-3" {
		t.Fatalf("unexpected tcp_stack payload: %v", got)
	}
}

func TestIPv6BucketSeparatesHopLimitFromTTL(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.jsonl")
	if err := writeBucket(file, "s", "eth0", time.Now().UTC().Truncate(time.Second), map[bucketKey]int{{IP: "2001:db8::1", Version: 6, TTL: 63, Direction: "outbound"}: 3}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var event normalized.Event
	if json.Unmarshal(raw, &event) != nil {
		t.Fatal("invalid standard event")
	}
	if event.Payload["ttl"] != nil || event.Payload["hop_limit"] != float64(63) || event.SourceEventType != "hop_limit" {
		t.Fatal("IPv6 reused IPv4 TTL field", event)
	}
}

func TestParseLLDPRouterSignal(t *testing.T) {
	frame := []byte{0x01, 0x80, 0xc2, 0, 0, 0x0e, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x88, 0xcc}
	frame = append(frame,
		0x02, 0x07, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x0a, 0x08, 'R', 'o', 'u', 't', 'e', 'r', '-', '1',
		0x0e, 0x04, 0, 0x14, 0, 0x14,
		0, 0,
	)
	signal, ok := parseControlFrame(frame)
	if !ok || signal.Kind != "lldp" || signal.MAC != "aa:bb:cc:dd:ee:ff" || signal.Payload["system_name"] != "Router-1" || signal.Payload["system_capabilities"] != "bridge,router" {
		t.Fatalf("unexpected LLDP signal: ok=%t signal=%+v", ok, signal)
	}
}

func TestParseVRRPRouterSignal(t *testing.T) {
	frame := make([]byte, 14+20+8)
	copy(frame[0:6], []byte{0x01, 0, 0x5e, 0, 0, 0x12})
	copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x12})
	frame[12], frame[13] = 0x08, 0
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 255, 112
	copy(ip[12:16], []byte{172, 20, 1, 1})
	copy(ip[16:20], []byte{224, 0, 0, 18})
	copy(frame[34:], []byte{0x21, 42, 110, 1, 0, 1, 0, 0})
	signal, ok := parseControlFrame(frame)
	if !ok || signal.Kind != "vrrp" || signal.IP != "172.20.1.1" || signal.Payload["virtual_router_id"] != 42 || signal.Payload["priority"] != 110 {
		t.Fatalf("unexpected VRRP signal: ok=%t signal=%+v", ok, signal)
	}
}

func TestParseSSDPResponseButNotClientSearch(t *testing.T) {
	build := func(payload string) []byte {
		frame := make([]byte, 14+20+8+len(payload))
		copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x13})
		frame[12], frame[13] = 0x08, 0
		ip := frame[14:34]
		ip[0], ip[9] = 0x45, 17
		copy(ip[12:16], []byte{172, 20, 1, 2})
		copy(ip[16:20], []byte{239, 255, 255, 250})
		udp := frame[34:42]
		udp[0], udp[1], udp[2], udp[3] = 0x07, 0x6c, 0x07, 0x6c
		copy(frame[42:], payload)
		return frame
	}
	response := "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: OpenWrt UPnP\r\n\r\n"
	signal, ok := parseControlFrame(build(response))
	if !ok || signal.Kind != "ssdp" || signal.Payload["st"] == nil || signal.Payload["server"] != "OpenWrt UPnP" {
		t.Fatalf("unexpected SSDP signal: ok=%t signal=%+v", ok, signal)
	}
	if _, ok = parseControlFrame(build("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n")); ok {
		t.Fatal("client M-SEARCH was incorrectly emitted as a device advertisement")
	}
}
