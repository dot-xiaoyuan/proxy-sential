package devicesignal

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

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
		s.add(o)
	}
	if len(s.samples) != 1 {
		t.Fatalf("retransmission became independent evidence: %d", len(s.samples))
	}
	o.EventID = "second"
	o.ObservedAt = at.Add(5 * time.Second)
	s.add(o)
	if len(s.samples) != 2 {
		t.Fatal("independent event lost")
	}
}

func TestHandshakeSummaryRetainsJA3AndJA4FromOnePacket(t *testing.T) {
	frame := buildTCPFrame([6]byte{2, 0, 0, 0, 0, 1}, [4]byte{192, 0, 2, 1}, 443, clientHello("test.example", "h2"))
	o, ok := parseHandshakeFrame(frame)
	if !ok || o.JA3 == "" || o.JA4 == "" {
		t.Fatalf("missing TLS fingerprints: %+v", o)
	}
	s := newHandshakeSummary()
	s.add(o)
	if len(s.samples) != 2 || s.samples["ja3/"+o.EventID].Value != o.JA3 || s.samples["ja4/"+o.EventID].Value != o.JA4 {
		t.Fatalf("fingerprint evidence lost: %+v", s.samples)
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
	bucket := newCaptureBucket()
	bucket.handshakeFeatureSamples = maxHandshakeFeatureSamples
	bucket.addHandshake(frame)
	for _, summary := range bucket.handshakes {
		if len(summary.samples) != 0 || summary.overflow == 0 {
			t.Fatal("global feature cap did not fail coverage closed")
		}
	}
}
