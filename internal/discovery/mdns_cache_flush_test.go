package discovery

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func flushAddress(name string, address [4]byte, ttl uint32) dnsmessage.Resource {
	record := coverageDNSAddress(name, ttl)
	record.Body = &dnsmessage.AResource{A: address}
	record.Header.Class |= 0x8000
	return record
}

func TestMDNSFullCacheFlushRecoversChangedServiceAddressOnRepeat(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scope := dnsCacheNamespace(source, "", "10.1.2.99")
	service := coverageDNSSRV(600)
	oldAddress := flushAddress("printer.local.", [4]byte{10, 1, 2, 3}, 600)
	newAddress := flushAddress("printer.local.", [4]byte{10, 1, 2, 4}, 600)
	for _, record := range []dnsmessage.Resource{service, oldAddress} {
		if decoder.DNS.observe(scope, record, at) {
			t.Fatal("initial service dependency was not retained")
		}
	}
	for i := 0; i < dnsCacheMaxRecords-2; i++ {
		if decoder.DNS.observe(scope, coverageDNSAddress(fmt.Sprintf("host-%d.local.", i), 600), at) {
			t.Fatalf("cache filled before record %d", i)
		}
	}
	if len(decoder.DNS.records) != dnsCacheMaxRecords {
		t.Fatalf("unexpected cache size %d", len(decoder.DNS.records))
	}
	first := decoder.Decode(coverageMDNSFrame(t, newAddress), source, at.Add(2*time.Second))
	currentAddressSeen := false
	for _, event := range first {
		currentAddressSeen = currentAddressSeen || str(event.Subject, "ip") == "10.1.2.4"
	}
	if !currentAddressSeen || decoder.DNS.stats.NotRetainedByRecordLimit.A != 1 {
		t.Fatalf("first announcement did not expose capacity loss: %+v %+v", first, decoder.DNS.stats)
	}
	if repeat := decoder.Decode(coverageMDNSFrame(t, newAddress), source, at.Add(2*time.Second)); !reflect.DeepEqual(first, repeat) {
		t.Fatalf("same packet at the same time changed deterministic evidence order: first=%+v repeat=%+v", first, repeat)
	}
	oldKey, newKey := dnsCacheRecordKey(scope, oldAddress), dnsCacheRecordKey(scope, newAddress)
	if decoder.DNS.records[oldKey] == nil {
		t.Fatal("cache-flush removed old address before one-second grace")
	}
	if decoder.DNS.records[newKey] != nil {
		t.Fatal("full cache exceeded record budget to retain new address")
	}
	decoder.Decode(coverageMDNSFrame(t, newAddress), source, at.Add(4*time.Second))
	if decoder.DNS.records[oldKey] != nil || decoder.DNS.records[newKey] == nil || len(decoder.DNS.records) != dnsCacheMaxRecords || decoder.DNS.bytes > dnsCacheMaxBytes {
		t.Fatalf("repeat did not replace obsolete address within the same budget: old=%v new=%v records=%d bytes=%d", decoder.DNS.records[oldKey] != nil, decoder.DNS.records[newKey] != nil, len(decoder.DNS.records), decoder.DNS.bytes)
	}
	resolved := decoder.Decode(coverageMDNSFrame(t, service), source, at.Add(5*time.Second))
	if len(resolved) != 1 || str(resolved[0].Subject, "ip") != "10.1.2.4" {
		t.Fatalf("cross-message service still used stale address: %+v", resolved)
	}
	assertDNSCacheIndexes(t, &decoder.DNS)
}

func TestMDNSFullCacheFlushSurvivesDuplicateRecordWithBitOnlyOnSecondCopy(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scope := dnsCacheNamespace(source, "", "10.1.2.99")
	service := coverageDNSSRV(600)
	oldAddress := flushAddress("printer.local.", [4]byte{10, 1, 2, 3}, 600)
	newAddress := flushAddress("printer.local.", [4]byte{10, 1, 2, 4}, 600)
	withoutFlush := newAddress
	withoutFlush.Header.Class = dnsmessage.ClassINET
	for _, record := range []dnsmessage.Resource{service, oldAddress} {
		if decoder.DNS.observe(scope, record, at) {
			t.Fatal("initial service dependency was not retained")
		}
	}
	for i := 0; i < dnsCacheMaxRecords-2; i++ {
		if decoder.DNS.observe(scope, coverageDNSAddress(fmt.Sprintf("host-%d.local.", i), 600), at) {
			t.Fatalf("cache filled before record %d", i)
		}
	}
	// Both wire records have the same cache key. The output de-duplicates them,
	// but the second copy's flush bit must still retire the stale RRSet member.
	decoder.Decode(coverageMDNSFrame(t, withoutFlush, newAddress), source, at.Add(2*time.Second))
	if decoder.DNS.records[dnsCacheRecordKey(scope, oldAddress)] == nil || decoder.DNS.records[dnsCacheRecordKey(scope, newAddress)] != nil {
		t.Fatal("the first announcement must respect the full budget and grace period")
	}
	decoder.Decode(coverageMDNSFrame(t, withoutFlush), source, at.Add(4*time.Second))
	if decoder.DNS.records[dnsCacheRecordKey(scope, oldAddress)] != nil || decoder.DNS.records[dnsCacheRecordKey(scope, newAddress)] == nil {
		t.Fatal("flush bit on the duplicate copy was lost before cache admission")
	}
	resolved := decoder.Decode(coverageMDNSFrame(t, service), source, at.Add(5*time.Second))
	if len(resolved) != 1 || str(resolved[0].Subject, "ip") != "10.1.2.4" {
		t.Fatalf("cross-message service used stale address: %+v", resolved)
	}
	assertDNSCacheIndexes(t, &decoder.DNS)
}

func TestMDNSCacheFlushPreservesRecentRRSetMembersAndTTL0(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scope := dnsCacheNamespace(source, "", "10.1.2.99")
	first := flushAddress("printer.local.", [4]byte{10, 1, 2, 3}, 600)
	second := flushAddress("printer.local.", [4]byte{10, 1, 2, 4}, 600)
	decoder.Decode(coverageMDNSFrame(t, first), source, at)
	decoder.Decode(coverageMDNSFrame(t, second), source, at.Add(500*time.Millisecond))
	decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(600)), source, at.Add(2*time.Second))
	if decoder.DNS.records[dnsCacheRecordKey(scope, first)] == nil || decoder.DNS.records[dnsCacheRecordKey(scope, second)] == nil {
		t.Fatal("cache-flush removed another RRSet member announced within one second")
	}
	goodbye := first
	goodbye.Header.TTL = 0
	decoder.Decode(coverageMDNSFrame(t, goodbye), source, at.Add(3*time.Second))
	if decoder.DNS.records[dnsCacheRecordKey(scope, first)] != nil || decoder.DNS.records[dnsCacheRecordKey(scope, second)] == nil {
		t.Fatal("TTL 0 did not withdraw only the named record")
	}
	assertDNSCacheIndexes(t, &decoder.DNS)
}

func TestMDNSCacheFlushIgnoresSharedPTRAndLegacyUnicast(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scope := dnsCacheNamespace(source, "", "10.1.2.99")
	oldPTR := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("_ipp._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 600}, Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("old._ipp._tcp.local.")}}
	newPTR := oldPTR
	newPTR.Header.Class |= 0x8000 // invalid on shared PTR; never flush siblings
	newPTR.Body = &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("new._ipp._tcp.local.")}
	decoder.Decode(coverageMDNSFrame(t, oldPTR), source, at)
	decoder.Decode(coverageMDNSFrame(t, newPTR), source, at.Add(2*time.Second))
	oldAddress := flushAddress("printer.local.", [4]byte{10, 1, 2, 3}, 600)
	newAddress := flushAddress("printer.local.", [4]byte{10, 1, 2, 4}, 600)
	decoder.Decode(coverageMDNSFrame(t, oldAddress), source, at)
	unicast := coverageMDNSFrame(t, newAddress)
	unicast[36], unicast[37] = 0x30, 0x39 // response to UDP destination 12345
	decoder.Decode(unicast, source, at.Add(2*time.Second))
	decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(600)), source, at.Add(4*time.Second))
	if decoder.DNS.records[dnsCacheRecordKey(scope, oldPTR)] == nil || decoder.DNS.records[dnsCacheRecordKey(scope, oldAddress)] == nil {
		t.Fatal("shared PTR or legacy unicast response flushed a retained record")
	}
	assertDNSCacheIndexes(t, &decoder.DNS)
}

func TestMDNSCacheFlushKeepsSamePacketAndOtherScopeMembers(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	otherSource := source
	otherSource.ID = "other-mirror"
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	first := flushAddress("printer.local.", [4]byte{10, 1, 2, 3}, 600)
	second := flushAddress("printer.local.", [4]byte{10, 1, 2, 4}, 600)
	scope := dnsCacheNamespace(source, "", "10.1.2.99")
	otherScope := dnsCacheNamespace(otherSource, "", "10.1.2.99")
	decoder.Decode(coverageMDNSFrame(t, first), source, at)
	decoder.Decode(coverageMDNSFrame(t, first), otherSource, at)
	decoder.Decode(coverageMDNSFrame(t, first, second), source, at.Add(2*time.Second))
	decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(600)), source, at.Add(4*time.Second))
	decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(600)), otherSource, at.Add(4*time.Second))
	if decoder.DNS.records[dnsCacheRecordKey(scope, first)] == nil || decoder.DNS.records[dnsCacheRecordKey(scope, second)] == nil || decoder.DNS.records[dnsCacheRecordKey(otherScope, first)] == nil {
		t.Fatal("same-packet renewal or separate capture scope was flushed")
	}
	assertDNSCacheIndexes(t, &decoder.DNS)
}

func TestMDNSCacheFlushAppliesOnlyToMatchingINUniqueRRSet(t *testing.T) {
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scope := dnsCacheNamespace(source, "", "10.1.2.99")
	oldA := flushAddress("printer.local.", [4]byte{10, 1, 2, 3}, 600)
	newA := flushAddress("printer.local.", [4]byte{10, 1, 2, 4}, 600)
	oldAAAA := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: oldA.Header.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 600}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0xfd, 0, 0, 1}}}
	newAAAA := oldAAAA
	newAAAA.Header.Class |= 0x8000
	newAAAA.Body = &dnsmessage.AAAAResource{AAAA: [16]byte{0xfd, 0, 0, 2}}
	oldSRV := coverageDNSSRV(600)
	newSRV := oldSRV
	newSRV.Header.Class |= 0x8000
	newSRV.Body = &dnsmessage.SRVResource{Port: 9100, Target: dnsmessage.MustNewName("printer.local.")}
	oldTXT := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: oldSRV.Header.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 600}, Body: &dnsmessage.TXTResource{TXT: []string{"model=old"}}}
	newTXT := oldTXT
	newTXT.Header.Class |= 0x8000
	newTXT.Body = &dnsmessage.TXTResource{TXT: []string{"model=new"}}
	for _, pair := range [][2]dnsmessage.Resource{{oldA, newA}, {oldAAAA, newAAAA}, {oldSRV, newSRV}, {oldTXT, newTXT}} {
		var decoder FrameDecoder
		decoder.Decode(coverageMDNSFrame(t, pair[0]), source, at)
		decoder.Decode(coverageMDNSFrame(t, pair[1]), source, at.Add(2*time.Second))
		decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("trigger.local.", 120)), source, at.Add(4*time.Second))
		if decoder.DNS.records[dnsCacheRecordKey(scope, pair[0])] != nil || decoder.DNS.records[dnsCacheRecordKey(scope, pair[1])] == nil {
			t.Fatalf("unique RRSet %s did not age its old value", pair[0].Header.Type)
		}
		assertDNSCacheIndexes(t, &decoder.DNS)
	}
	var decoder FrameDecoder
	decoder.Decode(coverageMDNSFrame(t, oldA, oldAAAA), source, at)
	foreignClass := newA
	foreignClass.Header.Class = dnsmessage.ClassCHAOS | 0x8000
	decoder.Decode(coverageMDNSFrame(t, foreignClass), source, at.Add(2*time.Second))
	decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("trigger.local.", 120)), source, at.Add(4*time.Second))
	if decoder.DNS.records[dnsCacheRecordKey(scope, oldA)] == nil || decoder.DNS.records[dnsCacheRecordKey(scope, oldAAAA)] == nil {
		t.Fatal("non-IN class or another RR type flushed an IN address")
	}
}

func TestMDNSCacheFlushLargeRRSetKeepsExpiryHeapConsistent(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	scope := dnsCacheNamespace(source, "", "10.1.2.99")
	for i := 0; i < 40; i++ {
		record := flushAddress("printer.local.", [4]byte{10, 1, 2, byte(i)}, 600)
		decoder.Decode(coverageMDNSFrame(t, record), source, at)
	}
	newAddress := flushAddress("printer.local.", [4]byte{10, 1, 3, 1}, 600)
	decoder.Decode(coverageMDNSFrame(t, newAddress), source, at.Add(2*time.Second))
	decoder.DNS.expire(at.Add(3*time.Second - time.Nanosecond))
	if len(decoder.DNS.records) != 41 {
		t.Fatalf("large RRSet expired before one-second grace: %d", len(decoder.DNS.records))
	}
	decoder.DNS.expire(at.Add(3 * time.Second))
	if len(decoder.DNS.records) != 1 || decoder.DNS.records[dnsCacheRecordKey(scope, newAddress)] == nil {
		t.Fatalf("large RRSet left stale heap entries: %d", len(decoder.DNS.records))
	}
	assertDNSCacheIndexes(t, &decoder.DNS)
}

func BenchmarkMDNSCacheFlushAtRecordLimit(b *testing.B) {
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	current := flushAddress("printer.local.", [4]byte{10, 1, 2, 3}, 600)
	message := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{current}}
	body, err := message.Pack()
	if err != nil {
		b.Fatal(err)
	}
	// The reusable frame has the same multicast response framing as the replay.
	frame := make([]byte, 42+len(body))
	copy(frame[6:12], []byte{2, 1, 2, 3, 4, 5})
	frame[12], frame[13], frame[14], frame[23] = 0x08, 0, 0x45, 17
	frame[16], frame[17] = byte((28+len(body))>>8), byte(28+len(body))
	copy(frame[26:30], []byte{10, 1, 2, 99})
	frame[34], frame[35], frame[36], frame[37] = 0x14, 0xe9, 0x14, 0xe9
	frame[38], frame[39] = byte((8+len(body))>>8), byte(8+len(body))
	copy(frame[42:], body)
	for _, dense := range []bool{false, true} {
		label := "sparse_owner"
		if dense {
			label = "dense_owner"
		}
		b.Run(label, func(b *testing.B) {
			var decoder FrameDecoder
			scope := dnsCacheNamespace(source, "", "10.1.2.99")
			for i := 0; i < dnsCacheMaxRecords; i++ {
				name := fmt.Sprintf("host-%d.local.", i)
				if dense {
					name = "printer.local."
				}
				record := coverageDNSAddress(name, 600)
				record.Body = &dnsmessage.AResource{A: [4]byte{10, 1, byte(i >> 8), byte(i)}}
				if decoder.DNS.observe(scope, record, at) {
					b.Fatalf("cache filled before %d", i)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(frame, source, at.Add(2*time.Second))
			}
		})
	}
}
