package discovery

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestMDNSV1FullCacheCountsCrossMessageServiceGap(t *testing.T) {
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	service, address := coverageDNSSRV(120), coverageDNSAddress("printer.local.", 120)

	baseline := newCaptureFrameDecoder(false)
	baseline.Decode(coverageMDNSFrame(t, service), source, at)
	resolved := baseline.Decode(coverageMDNSFrame(t, address), source, at.Add(time.Second))
	if len(resolved) != 1 || str(resolved[0].Subject, "ip") != "10.1.2.3" || str(resolved[0].Payload, "service_type") != "_ipp._tcp" {
		t.Fatalf("baseline two-message service did not resolve: %+v", resolved)
	}

	full := newCaptureFrameDecoder(false)
	for i := 0; i < dnsCacheMaxRecords; i++ {
		if full.DNS.observe("mirror|campus|access||", coverageDNSAddress(fmt.Sprintf("cached-%d.local.", i), 600), at) {
			t.Fatalf("cache filled before record %d", i)
		}
	}
	first := full.Decode(coverageMDNSFrame(t, service), source, at)
	if len(first) != 1 || str(first[0].Subject, "ip") != "" {
		t.Fatalf("full cache changed the current SRV packet: %+v", first)
	}
	second := full.Decode(coverageMDNSFrame(t, address), source, at.Add(time.Second))
	if len(second) != 0 {
		t.Fatalf("v1 invented a resolved service without retained SRV: %+v", second)
	}
	stats := full.DNS.captureStats()
	if stats.RetainedByKind != (DNSCacheRecordKinds{A: dnsCacheMaxRecords}) {
		t.Fatalf("retained record kinds do not describe full cache: %+v", stats.RetainedByKind)
	}
	if stats.RecordsNotRetained != 2 || stats.MessagesWithRecordsNotRetained != 2 ||
		stats.NotRetainedByRecordLimit.SRV != 1 || stats.NotRetainedByRecordLimit.A != 1 ||
		stats.NotRetainedByByteLimit.SRV != 0 || stats.Records != dnsCacheMaxRecords {
		t.Fatalf("record-limit type counters lost the correlation gap: %+v", stats)
	}
	raw, err := json.Marshal(stats)
	if err != nil || !strings.Contains(string(raw), `"not_retained_by_record_limit":{"a":1`) {
		t.Fatalf("capture.stats omitted fixed record-limit counters: %s %v", raw, err)
	}
}

func TestMDNSCacheByteHeadroomCountsSupportedRecordTypes(t *testing.T) {
	decoder := newCaptureFrameDecoder(false)
	// Isolate the byte admission gate without allocating a full-budget fixture.
	decoder.DNS.bytes = dnsCacheMaxBytes - 1
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	address := coverageDNSAddress("printer.local.", 120)
	var v6 [16]byte
	v6[0], v6[1], v6[15] = 0xfd, 0x00, 1
	aaaa := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: address.Header.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AAAAResource{AAAA: v6}}
	ptr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("_ipp._tcp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("service._ipp._tcp.local.")}}
	txt := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("service._ipp._tcp.local."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"note=present"}}}
	events := decoder.Decode(coverageMDNSFrame(t, address, aaaa, ptr, coverageDNSSRV(120), txt), source, at)
	if len(events) == 0 || str(events[0].Subject, "ip") == "" {
		t.Fatalf("byte-limit telemetry suppressed current-message resolution: %+v", events)
	}
	stats := decoder.DNS.captureStats()
	if stats.RecordsNotRetained != 5 || stats.MessagesWithRecordsNotRetained != 1 || stats.NotRetainedByByteLimit != (DNSCacheRecordKinds{A: 1, AAAA: 1, PTR: 1, SRV: 1, TXT: 1}) || stats.NotRetainedByRecordLimit != (DNSCacheRecordKinds{}) {
		t.Fatalf("byte-limit reason or fixed record-type counters incorrect: %+v", stats)
	}
}
