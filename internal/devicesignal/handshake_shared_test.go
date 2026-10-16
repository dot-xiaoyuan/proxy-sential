package devicesignal

import (
	"crypto/md5"
	"encoding/hex"
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
