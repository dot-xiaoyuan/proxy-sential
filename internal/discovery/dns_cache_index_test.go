package discovery

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"proxy-sentinel/internal/normalized"
)

func TestMDNSIndexARecordCompletesPreviouslyCachedService(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	first := decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120)), source, at)
	if len(first) != 1 || str(first[0].Subject, "ip") != "" {
		t.Fatalf("unexpected initial unresolved service: %+v", first)
	}
	completed := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), source, at.Add(time.Second))
	if len(completed) != 1 || isMDNSHostAnnouncement(completed[0]) || str(completed[0].Subject, "ip") != "10.1.2.3" || str(completed[0].Payload, "service_type") != "_ipp._tcp" {
		t.Fatalf("A-only packet failed to complete its cached service: %+v", completed)
	}
}

func TestMDNSIndexDoesNotJoinAcrossCaptureNamespaceOrAnnouncer(t *testing.T) {
	for _, dimension := range []string{"source", "node", "site", "domain", "interface", "vlan", "announcer"} {
		t.Run(dimension, func(t *testing.T) {
			var decoder FrameDecoder
			source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
			at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
			decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120)), source, at)
			other := source
			frame := coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120))
			switch dimension {
			case "source":
				other.ID = "another-mirror"
			case "node":
				other.Node = "another-sensor"
			case "site":
				other.Site = "another-campus"
			case "domain":
				other.Domain = "another-access"
			case "interface":
				other.Address = "mirror1"
			case "vlan":
				tagged := make([]byte, len(frame)+4)
				copy(tagged, frame[:12])
				binary.BigEndian.PutUint16(tagged[12:14], 0x8100)
				binary.BigEndian.PutUint16(tagged[14:16], 100)
				copy(tagged[16:], frame[12:])
				frame = tagged
			case "announcer":
				frame[29] = 100
			}
			events := decoder.Decode(frame, other, at.Add(time.Second))
			if len(events) != 1 || !isMDNSHostAnnouncement(events[0]) {
				t.Fatalf("unrelated namespace/announcer completed another service: %+v", events)
			}
		})
	}
}

func TestMDNSIndexNamespaceEncodingHasNoSeparatorAmbiguity(t *testing.T) {
	var decoder FrameDecoder
	first := Source{ID: "mirror|campus", Node: "sensor", Site: "access", Domain: "x", Address: "mirror0"}
	second := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access|x", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120)), first, at)
	events := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), second, at.Add(time.Second))
	if len(events) != 1 || !isMDNSHostAnnouncement(events[0]) {
		t.Fatalf("scope fields containing separators were joined: %+v", events)
	}
}

func TestMDNSIndexServiceWithdrawalAndExpiryRemoveDependency(t *testing.T) {
	for _, expired := range []bool{false, true} {
		var decoder FrameDecoder
		source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
		at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(2)), source, at)
		if !expired {
			decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(0)), source, at.Add(time.Second))
		}
		events := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), source, at.Add(2*time.Second))
		if len(events) != 1 || !isMDNSHostAnnouncement(events[0]) {
			t.Fatalf("expired=%v retained a service dependency: %+v", expired, events)
		}
	}
}

func assertDNSCacheIndexes(t *testing.T, cache *DNSCache) {
	t.Helper()
	if len(cache.expiry) != len(cache.records) || len(cache.records) > dnsCacheMaxRecords {
		t.Fatalf("expiry nodes are not bounded by live records: nodes=%d records=%d", len(cache.expiry), len(cache.records))
	}
	bytes, srvCount, ptrCount := 0, 0, 0
	for i, entry := range cache.expiry {
		if entry.expiryIndex != i || cache.records[entry.key] != entry {
			t.Fatal("heap slot lost its authoritative record")
		}
		if i > 0 && entry.expires.Before(cache.expiry[(i-1)/2].expires) {
			t.Fatal("expiry heap ordering is invalid")
		}
	}
	for key, entry := range cache.records {
		bytes += dnsCacheEntryBytes(key, entry.record)
		if _, found := cache.byOwner[dnsOwnerKey{entry.scope, entry.owner}][key]; !found {
			t.Fatal("live record absent from owner index")
		}
		switch entry.record.Body.(type) {
		case *dnsmessage.SRVResource:
			srvCount++
			if _, found := cache.srvByTarget[dnsOwnerKey{entry.scope, entry.target}][key]; !found {
				t.Fatal("service absent from reverse index")
			}
		case *dnsmessage.PTRResource:
			ptrCount++
			if _, found := cache.ptrByTarget[dnsOwnerKey{entry.scope, entry.target}][key]; !found {
				t.Fatal("PTR absent from reverse index")
			}
		}
	}
	for _, check := range []struct {
		index dnsRecordIndex
		count int
	}{{cache.byOwner, len(cache.records)}, {cache.srvByTarget, srvCount}, {cache.ptrByTarget, ptrCount}} {
		members := 0
		for _, keys := range check.index {
			if len(keys) == 0 {
				t.Fatal("empty owner bucket was retained")
			}
			members += len(keys)
			for key := range keys {
				if cache.records[key] == nil {
					t.Fatal("index retained a removed record")
				}
			}
		}
		if members != check.count {
			t.Fatalf("wrong index membership count: got=%d want=%d", members, check.count)
		}
	}
	if cache.bytes != bytes || bytes > dnsCacheMaxBytes {
		t.Fatalf("wrong retained byte charge: stored=%d actual=%d", cache.bytes, bytes)
	}
}

func TestMDNSIndexGrowthRenewalWithdrawalAndExpiryStayBounded(t *testing.T) {
	var cache DNSCache
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < dnsCacheMaxRecords; i++ {
		record := coverageDNSAddress(fmt.Sprintf("host-%d.local.", i), uint32(i%5+1))
		switch i % 3 {
		case 1:
			record.Header.Type = dnsmessage.TypeSRV
			record.Body = &dnsmessage.SRVResource{Port: 631, Target: dnsmessage.MustNewName("target.local.")}
		case 2:
			record.Header.Type = dnsmessage.TypePTR
			record.Body = &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("service._ipp._tcp.local.")}
		}
		if cache.observe("scope|", record, at) {
			t.Fatalf("small record %d was rejected", i)
		}
	}
	assertDNSCacheIndexes(t, &cache)
	if !cache.observe("scope|", coverageDNSAddress("overflow.local.", 600), at) {
		t.Fatal("full record budget admitted a new key")
	}
	renewal := coverageDNSAddress("HOST-0.local.", 10)
	renewal.Header.Class |= 0x8000 // cache-flush bit is not a separate DNS class
	for i := 0; i < 2000; i++ {
		if cache.observe("scope|", renewal, at.Add(time.Duration(i)*time.Nanosecond)) {
			t.Fatal("same record could not renew at full record capacity")
		}
	}
	assertDNSCacheIndexes(t, &cache)
	removed := 0
	for _, entry := range cache.records {
		record := entry.record
		record.Header.TTL = 0
		cache.observe(entry.scope, record, at)
		removed++
		if removed == 500 {
			break
		}
	}
	cache.expire(at.Add(2 * time.Second))
	assertDNSCacheIndexes(t, &cache)
	cache.expire(at.Add(20 * time.Second))
	assertDNSCacheIndexes(t, &cache)
	if len(cache.records) != 0 || len(cache.byOwner) != 0 || len(cache.srvByTarget) != 0 || len(cache.ptrByTarget) != 0 {
		t.Fatal("expiry retained record/index metadata")
	}
}

func TestMDNSIndexExpiryRetainsRecordUntilExactDeadline(t *testing.T) {
	var cache DNSCache
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cache.observe("scope|", coverageDNSAddress("host.local.", 1), at)
	cache.expire(at.Add(time.Second - time.Nanosecond))
	if len(cache.records) != 1 {
		t.Fatal("record expired before its deadline")
	}
	cache.expire(at.Add(time.Second))
	assertDNSCacheIndexes(t, &cache)
	if len(cache.records) != 0 {
		t.Fatal("record remained at its expiry deadline")
	}
}

func TestMDNSIndexResolvesCachedTXTAndPTRAndKeepsNewestCorrection(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	srv := coverageDNSSRV(120)
	txt := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: srv.Header.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"model=old"}}}
	ptr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("_custom._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.PTRResource{PTR: srv.Header.Name}}
	decoder.Decode(coverageMDNSFrame(t, srv, txt, ptr), source, at)
	assertService := func(events []normalized.Event, wantTXT string) {
		t.Helper()
		if len(events) != 1 || str(events[0].Payload, "service_type") != "_custom._tcp" || str(events[0].Subject, "ip") != "10.1.2.3" {
			t.Fatalf("cross-packet service dependencies missing: %+v", events)
		}
		values, _ := events[0].Payload["txt"].([]string)
		if len(values) != 1 || values[0] != wantTXT {
			t.Fatalf("wrong TXT dependency: got=%v want=%s", values, wantTXT)
		}
	}
	assertService(decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), source, at.Add(time.Second)), "model=old")
	txt.Body = &dnsmessage.TXTResource{TXT: []string{"model=new"}}
	assertService(decoder.Decode(coverageMDNSFrame(t, txt), source, at.Add(2*time.Second)), "model=new")
	for range 20 {
		assertService(decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), source, at.Add(3*time.Second)), "model=new")
	}
	assertDNSCacheIndexes(t, &decoder.DNS)
}

func TestMDNSIndexDoesNotReadFutureServiceIntoEarlierPacket(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120)), source, at.Add(time.Second))
	events := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), source, at)
	if len(events) != 1 || !isMDNSHostAnnouncement(events[0]) {
		t.Fatalf("future cache observation was used for earlier evidence: %+v", events)
	}
}
