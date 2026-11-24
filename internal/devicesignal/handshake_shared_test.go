package devicesignal

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHandshakeV2ReservesFeatureBudgetForOutputDevices(t *testing.T) {
	state := newCaptureBucket()
	state.handshakeCaptureV2 = true
	at := time.Unix(1800, 0)
	for device := 0; device < 130; device++ {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(device + 1)})
		for sample := 0; sample < 288; sample++ {
			id := strconv.Itoa(sample)
			state.recordHandshake(handshakeObservation{IP: ip, JA3: id, EventID: id, ObservedAt: at})
		}
	}
	ip := netip.MustParseAddr("192.0.2.200")
	for i := 0; i < 300; i++ {
		state.recordHandshake(handshakeObservation{IP: ip, JA3: "selected", EventID: "retransmitted", ObservedAt: at})
	}
	keys := state.selectHandshakes(1, at, nil)
	if len(keys) != 1 || keys[0].IP != ip {
		t.Fatalf("selected keys = %v, want the most active device %s", keys, ip)
	}
	selected := state.handshakes[keys[0]]
	if len(selected.samples) != 1 || selected.overflow != 0 {
		t.Fatalf("selected device samples=%d overflow=%d", len(selected.samples), selected.overflow)
	}
	for key, summary := range state.handshakes {
		if key.IP != ip && len(summary.samples) != 0 {
			t.Fatalf("omitted device consumed samples: %s", key.IP)
		}
	}
}

func TestHandshakeV2CandidateLimitReportsCoverageGap(t *testing.T) {
	state := newCaptureBucket()
	state.handshakeCaptureV2 = true
	state.handshakeCandidateBytes = maxHandshakeCandidateBytes
	at := time.Unix(1800, 0)
	ip := netip.MustParseAddr("192.0.2.200")
	state.recordHandshake(handshakeObservation{IP: ip, JA3: "feature", EventID: "event", ObservedAt: at})
	keys := state.selectHandshakes(1, at, nil)
	summary := state.handshakes[keys[0]]
	if summary.overflow != 1 || len(summary.samples) != 0 {
		t.Fatalf("rejected candidate samples=%d overflow=%d", len(summary.samples), summary.overflow)
	}
	state.resetHandshakes()
	state.recordHandshake(handshakeObservation{IP: ip, JA3: "feature", EventID: "next-bucket", ObservedAt: at.Add(30 * time.Second)})
	keys = state.selectHandshakes(1, at.Add(30*time.Second), nil)
	if summary = state.handshakes[keys[0]]; summary.overflow != 0 || len(summary.samples) != 1 {
		t.Fatalf("next bucket samples=%d overflow=%d", len(summary.samples), summary.overflow)
	}
}

func TestHandshakeV2PrioritizesCompleteEvidenceAndRotatesRemainingKeys(t *testing.T) {
	state := newCaptureBucket()
	state.handshakeCaptureV2 = true
	start := time.Unix(1800, 0)
	complete := netip.MustParseAddr("192.0.2.10")
	partial := []netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("192.0.2.21")}
	state.recordHandshake(handshakeObservation{IP: complete, JA3: "full", EventID: "full", ObservedAt: start})
	for _, ip := range partial {
		for i := 0; i < 10; i++ {
			state.recordHandshake(handshakeObservation{IP: ip, Truncated: true, ObservedAt: start})
		}
	}
	seen := map[netip.Addr]bool{}
	for i := range 2 {
		keys := state.selectHandshakes(2, start.Add(time.Duration(i)*30*time.Second), nil)
		if len(keys) != 2 || keys[0].IP != complete {
			t.Fatalf("selection=%v, want the complete evidence and one rotating slot", keys)
		}
		seen[keys[1].IP] = true
	}
	for _, ip := range partial {
		if !seen[ip] {
			t.Fatalf("missing incomplete evidence from rotation: %s", ip)
		}
	}
}

func TestHandshakeJA3RequiresCompleteClientHello(t *testing.T) {
	raw := clientHello("test.example", "h2")
	want := md5.Sum([]byte("771,4865,0-16,,"))
	if got := clientHelloJA3(raw); got != hex.EncodeToString(want[:]) {
		t.Fatalf("JA3=%q", got)
	}
	for end := 0; end < len(raw); end++ {
		if got := clientHelloJA3(raw[:end]); got != "" {
			t.Fatalf("truncated at %d produced %s", end, got)
		}
	}
	malformed := append([]byte{}, raw...)
	malformed[8]++
	if clientHelloJA3(malformed) != "" {
		t.Fatal("invalid handshake length accepted")
	}
}

func TestHandshakeJA4RequiresCompleteClientHello(t *testing.T) {
	raw := clientHello("test.example", "h2")
	want := "t12d0102h2_0f2cb44170f4_000000000000"
	if got := clientHelloJA4(raw); got != want {
		t.Fatalf("JA4=%q, want %q", got, want)
	}
	for end := 0; end < len(raw); end++ {
		if got := clientHelloJA4(raw[:end]); got != "" {
			t.Fatalf("truncated at %d produced %s", end, got)
		}
	}
	malformed := append([]byte{}, raw...)
	malformed[8]++
	if got := clientHelloJA4(malformed); got != "" {
		t.Fatalf("invalid handshake length accepted: %s", got)
	}
}

func TestHandshakeJA4OfficialExtensionHashVector(t *testing.T) {
	extensions := []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	signatures := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	if got := ja4ExtensionHash(extensions, signatures); got != "e5627efa2ab1" {
		t.Fatalf("extension hash=%q", got)
	}
}

func TestHandshakeJA4SupportedVersionAndSignatureOrder(t *testing.T) {
	raw := clientHello("test.example", "h2")
	raw = appendClientHelloExtension(raw, 43, []byte{4, 0x03, 0x03, 0x03, 0x04})
	raw = appendClientHelloExtension(raw, 13, []byte{0, 4, 0x04, 0x03, 0x08, 0x04})
	got := clientHelloJA4(raw)
	if !strings.HasPrefix(got, "t13d0104h2_") || len(got) != 36 {
		t.Fatalf("JA4 supported version/signatures=%q", got)
	}
	if ja4ExtensionHash([]uint16{43, 13}, []uint16{0x0403, 0x0804}) == ja4ExtensionHash([]uint16{43, 13}, []uint16{0x0804, 0x0403}) {
		t.Fatal("signature algorithm order was lost")
	}
	if ja4ALPN([]byte{0x30, 0xab}) != "3b" || ja4ALPN([]byte{'x'}) != "xx" {
		t.Fatal("JA4 ALPN encoding differs from specification")
	}
}

func appendClientHelloExtension(raw []byte, kind uint16, data []byte) []byte {
	copyRaw := append([]byte(nil), raw...)
	pos := 9 + 34
	pos += 1 + int(copyRaw[pos])
	pos += 2 + int(binary.BigEndian.Uint16(copyRaw[pos:pos+2]))
	pos += 1 + int(copyRaw[pos])
	extLengthPos := pos
	result := append(copyRaw, byte(kind>>8), byte(kind), byte(len(data)>>8), byte(len(data)))
	result = append(result, data...)
	binary.BigEndian.PutUint16(result[extLengthPos:extLengthPos+2], binary.BigEndian.Uint16(copyRaw[extLengthPos:extLengthPos+2])+uint16(len(data)+4))
	binary.BigEndian.PutUint16(result[3:5], uint16(len(result)-5))
	size := len(result) - 9
	result[6], result[7], result[8] = byte(size>>16), byte(size>>8), byte(size)
	return result
}

func TestHandshakeFeatureSamplesDeduplicateRetransmission(t *testing.T) {
	at := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	s := newHandshakeSummary()
	o := handshakeObservation{UserAgent: "Mozilla/5.0 (Android; Pixel 8 Build/TEST)", EventID: "same", ObservedAt: at}
	for i := 0; i < 100; i++ {
		s.add(o, maxHandshakeFeatureSamples)
	}
	if len(s.samples) != 1 {
		t.Fatalf("retransmission became independent evidence: %d", len(s.samples))
	}
	o.EventID = "second"
	o.ObservedAt = at.Add(5 * time.Second)
	s.add(o, maxHandshakeFeatureSamples)
	if len(s.samples) != 2 {
		t.Fatal("independent event lost")
	}
}

func TestHandshakeSummaryRetainsJA3AndJA4FromOnePacket(t *testing.T) {
	frame := buildTCPFrame([6]byte{2, 0, 0, 0, 0, 1}, [4]byte{192, 0, 2, 1}, 443, clientHello("test.example", "h2"))
	o, ok := parseHandshakeFrame(frame)
	if !ok || o.JA3 == "" || o.JA4 == "" || o.DestinationPort != 443 {
		t.Fatalf("missing TLS fingerprints: %+v", o)
	}
	s := newHandshakeSummary()
	s.add(o, maxHandshakeFeatureSamples)
	if len(s.samples) != 2 || s.samples["ja3/"+o.EventID].Value != o.JA3 || s.samples["ja4/"+o.EventID].Value != o.JA4 || s.samples["ja3/"+o.EventID].DestinationPort != 443 || s.samples["ja4/"+o.EventID].DestinationPort != 443 {
		t.Fatalf("fingerprint evidence lost: %+v", s.samples)
	}
}

func TestHandshakeFingerprintsIgnoreFollowingTLSRecord(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	ip := [4]byte{192, 0, 2, 1}
	hello := clientHello("test.example", "h2")
	want, ok := parseHandshakeFrame(buildTCPFrame(mac, ip, 443, hello))
	if !ok || want.JA3 == "" || want.JA4 == "" {
		t.Fatal("ClientHello did not produce both fingerprints")
	}
	changeCipherSpec := []byte{20, 3, 3, 0, 1, 1}
	frame := buildTCPFrame(mac, ip, 443, append(hello, changeCipherSpec...))
	got, ok := parseHandshakeFrame(frame)
	if !ok || got.Truncated || got.JA3 != want.JA3 || got.JA4 != want.JA4 || got.SNI != want.SNI || got.ALPN != want.ALPN {
		t.Fatalf("following TLS record changed ClientHello fields: %+v", got)
	}
}

func TestHandshakeCompleteHeaderSurvivesClippedTrailingPayload(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	ip := [4]byte{192, 0, 2, 1}
	for _, tc := range []struct {
		name string
		port uint16
		head []byte
	}{
		{"TLS", 443, clientHello("test.example", "h2")},
		{"HTTP", 80, []byte("POST / HTTP/1.1\r\nHost: test.example\r\nUser-Agent: example\r\n\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := buildTCPFrame(mac, ip, tc.port, append(append([]byte(nil), tc.head...), make([]byte, 2200)...))
			full, ok := parseHandshakeFrame(frame)
			if !ok || full.Truncated {
				t.Fatal("complete frame did not produce a complete handshake")
			}
			got, disposition := classifyHandshakeFrame(frame[:2048])
			if disposition != handshakeObserved || got.Truncated || got.EventID != full.EventID || got.JA3 != full.JA3 || got.UserAgent != full.UserAgent {
				t.Fatalf("trailing payload affected evidence: %+v", got)
			}
			partial, disposition := classifyHandshakeFrame(frame[:len(frame)-2201])
			if disposition != handshakeObserved || !partial.Truncated {
				t.Fatalf("clipped header reported as complete: %+v", partial)
			}
		})
	}
}

func TestHandshakeOptionalMetadataLimitDoesNotReportMissingSamples(t *testing.T) {
	at := time.Date(2026, 11, 21, 1, 0, 0, 0, time.UTC)
	summary := newHandshakeSummary()
	for i := 0; i <= maxHandshakeValues; i++ {
		value := string(rune('a' + i))
		summary.add(handshakeObservation{SNI: value, JA3: strings.Repeat("a", 32), EventID: value, ObservedAt: at}, maxHandshakeFeatureSamples)
	}
	if len(summary.snis) != maxHandshakeValues || len(summary.samples) != 3 || summary.overflow != 0 || summary.metadataOmitted != 1 {
		t.Fatalf("optional SNI limit reported missing samples: %+v", summary)
	}
}

func TestHandshakeRealFrameRetransmissionAndBucketBudget(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	frame := buildTCPFrame(mac, [4]byte{192, 0, 2, 1}, 80, []byte("GET / HTTP/1.1\r\nHost: test.example\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14; SM-S9280 Build/TEST)\r\n\r\n"))
	a, ok := parseHandshakeFrame(frame)
	if !ok || a.Truncated || a.UserAgent == "" {
		t.Fatal("real HTTP structure not parsed")
	}
	// ACK/checksum changes do not make a retransmitted payload independent.
	copied := append([]byte{}, frame...)
	copied[14+20+8]++
	copied[14+20+16]++
	b, ok := parseHandshakeFrame(copied)
	if !ok || a.EventID != b.EventID {
		t.Fatal("TCP retransmission changed dedup key")
	}
	copied[14+20+4]++
	c, ok := parseHandshakeFrame(copied)
	if !ok || c.EventID == a.EventID {
		t.Fatal("new TCP sequence did not change event key")
	}
	partial := newCaptureBucket()
	partial.addHandshake(frame)
	partial.handshakeFeatureSamples = maxHandshakeFeatureSamples
	partial.addHandshake(frame)
	for _, summary := range partial.handshakes {
		if len(summary.samples) != 1 || summary.overflow != 0 {
			t.Fatal("duplicate observation incorrectly signaled feature loss at the global cap")
		}
	}
	partial.addHandshake(copied)
	for _, summary := range partial.handshakes {
		if len(summary.samples) != 1 || summary.overflow != 1 {
			t.Fatal("an eligible new observation was not reported as omitted")
		}
	}
	bucket := newCaptureBucket()
	bucket.handshakeFeatureSamples = maxHandshakeFeatureSamples
	bucket.addHandshake(frame)
	for _, summary := range bucket.handshakes {
		if len(summary.samples) != 0 || summary.overflow == 0 {
			t.Fatal("global feature cap did not fail coverage closed")
		}
	}
}
