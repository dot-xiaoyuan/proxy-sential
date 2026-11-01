package discovery

import (
	"fmt"
	"testing"
	"time"
)

// Measure expiry bookkeeping under the same bounded full cache, without
// packet-key formatting, service decoding, or any disk/network operation.
func BenchmarkFragmentFullCacheReject(b *testing.B) {
	var d FrameDecoder
	at := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	payload := make([]byte, 8)
	for i := range 256 {
		d.fragment(fmt.Sprintf("orphan-%d", i), nil, payload, 8, true, 14, false, at)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.fragment("unrelated-tail", nil, payload, 8, true, 14, false, at)
	}
}

func BenchmarkFragmentCompletedDatagrams(b *testing.B) {
	var d FrameDecoder
	at := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	payload := make([]byte, 8)
	header := make([]byte, 34)
	for i := range 255 {
		d.fragment(fmt.Sprintf("orphan-%d", i), nil, payload, 8, true, 14, false, at)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.fragment("supported", header, payload, 0, true, 14, false, at)
		if d.fragment("supported", nil, payload, 8, false, 14, false, at) == nil {
			b.Fatal("completed datagram missing")
		}
	}
}
