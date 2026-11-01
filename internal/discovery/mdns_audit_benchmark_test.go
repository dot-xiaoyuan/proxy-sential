package discovery

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func BenchmarkMDNSHostPacketWithRetainedCache(b *testing.B) {
	benchmarkMDNSAddressPacketWithRetainedCache(b, false)
}

func BenchmarkMDNSServiceAddressPacketWithRetainedCache(b *testing.B) {
	benchmarkMDNSAddressPacketWithRetainedCache(b, true)
}

func benchmarkMDNSAddressPacketWithRetainedCache(b *testing.B, service bool) {
	message := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{coverageDNSAddress("printer.local.", 120)}}
	body, err := message.Pack()
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, 42+len(body))
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14], frame[23] = 0x45, 17
	binary.BigEndian.PutUint16(frame[16:18], uint16(28+len(body)))
	copy(frame[26:30], []byte{10, 1, 2, 99})
	binary.BigEndian.PutUint16(frame[34:36], 5353)
	binary.BigEndian.PutUint16(frame[36:38], 5353)
	binary.BigEndian.PutUint16(frame[38:40], uint16(8+len(body)))
	copy(frame[42:], body)
	baseRecords := 1
	if service {
		baseRecords++
	}
	for _, records := range []int{baseRecords, dnsCacheMaxRecords} {
		b.Run(fmt.Sprintf("records_%d", records), func(b *testing.B) {
			var decoder FrameDecoder
			source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
			at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
			namespace := dnsCacheNamespace(source, "", "10.1.2.99")
			decoder.DNS.observe(namespace, message.Answers[0], at)
			if service {
				decoder.DNS.observe(namespace, coverageDNSSRV(120), at)
			}
			for i := baseRecords; i < records; i++ {
				decoder.DNS.observe(namespace, coverageDNSAddress(fmt.Sprintf("host-%d.local.", i), 600), at)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if events := decoder.Decode(frame, source, at.Add(time.Second)); len(events) != 1 || isMDNSHostAnnouncement(events[0]) == service {
					b.Fatalf("unexpected host output: %d", len(events))
				}
			}
		})
	}
}
