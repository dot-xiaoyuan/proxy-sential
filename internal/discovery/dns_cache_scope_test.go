package discovery

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func scopeTestAddress(name string, ip [4]byte, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.AResource{A: ip},
	}
}

func TestMDNSCaptureCacheSkipsOutOfScopeAddressFloodBeforeService(t *testing.T) {
	allow, err := ParseCaptureCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	decoder := newCaptureFrameDecoder(false, allow...)
	for i := 0; i < 10000; i++ {
		if decoder.DNS.observe("other-scope", scopeTestAddress(fmt.Sprintf("outside-%d.local.", i), [4]byte{192, 0, 2, 1}, 600), at) {
			t.Fatal("out-of-scope address was treated as a budget failure")
		}
	}
	if len(decoder.DNS.records) != 0 || decoder.DNS.bytes != 0 {
		t.Fatalf("out-of-scope addresses consumed cache: %d records, %d bytes", len(decoder.DNS.records), decoder.DNS.bytes)
	}
	stats := decoder.DNS.captureStats()
	if stats.SkippedOutOfScope.A != 10000 || stats.RecordsNotRetained != 0 || stats.NotRetainedByRecordLimit != (DNSCacheRecordKinds{}) {
		t.Fatalf("scope skips were mixed with capacity failures: %+v", stats)
	}
	raw, err := json.Marshal(stats)
	if err != nil || !strings.Contains(string(raw), `"skipped_out_of_scope":{"a":10000`) {
		t.Fatalf("scope skips did not serialize as capture stats: %s %v", raw, err)
	}
	first := filterCaptureEvents(decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120)), source, at), allow)
	if len(first) != 0 { // Addressless v1 service remains outside the CIDR display boundary.
		t.Fatalf("addressless service bypassed CIDR filtering: %+v", first)
	}
	second := filterCaptureEvents(decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), source, at.Add(time.Second)), allow)
	if len(second) != 1 || str(second[0].Subject, "ip") != "10.1.2.3" || str(second[0].Payload, "service_type") != "_ipp._tcp" {
		t.Fatalf("out-of-scope cache pressure lost in-scope cross-message service: %+v", second)
	}
	other := source
	other.Node = "other-sensor"
	isolation := filterCaptureEvents(decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), other, at.Add(2*time.Second)), allow)
	if len(isolation) != 0 {
		t.Fatalf("another capture scope joined cached service: %+v", isolation)
	}
}

func TestMDNSCaptureCacheScopeChecksAAAAAndMappedAddress(t *testing.T) {
	allow, err := ParseCaptureCIDRs("10.0.0.0/8,fd00::/8")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	decoder := newCaptureFrameDecoder(false, allow...)
	makeAAAA := func(name, address string) dnsmessage.Resource {
		ip := netip.MustParseAddr(address).As16()
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.AAAAResource{AAAA: ip},
		}
	}
	for _, record := range []dnsmessage.Resource{
		makeAAAA("inside-v6.local.", "fd00::1"),
		makeAAAA("mapped-v4.local.", "::ffff:10.1.2.3"),
		makeAAAA("outside-v6.local.", "fe80::1"),
	} {
		if decoder.DNS.observe("scope", record, at) {
			t.Fatal("scope filtering masqueraded as a capacity failure")
		}
	}
	stats := decoder.DNS.captureStats()
	if stats.Records != 2 || stats.SkippedOutOfScope.AAAA != 1 || stats.RecordsNotRetained != 0 {
		t.Fatalf("AAAA or mapped IPv4 scope diverged from output CIDR rule: %+v", stats)
	}
}

func TestMDNSCaptureCacheScopePreservesCurrentAndFutureInScopeOutput(t *testing.T) {
	allow, err := ParseCaptureCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	scoped := newCaptureFrameDecoder(false, allow...)
	unscoped := newCaptureFrameDecoder(false)
	service := coverageDNSSRV(120)
	inside := coverageDNSAddress("printer.local.", 120)
	outside := scopeTestAddress("printer.local.", [4]byte{192, 0, 2, 1}, 120)
	for _, records := range [][]dnsmessage.Resource{{service, inside, outside}, {service}} {
		frame := coverageMDNSFrame(t, records...)
		got := filterCaptureEvents(scoped.Decode(frame, source, at), allow)
		want := filterCaptureEvents(unscoped.Decode(frame, source, at), allow)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("scope-aware cache changed in-scope output: got=%+v want=%+v", got, want)
		}
		at = at.Add(time.Second)
	}
	if scoped.DNS.captureStats().SkippedOutOfScope.A != 1 || unscoped.DNS.captureStats().SkippedOutOfScope.A != 0 {
		t.Fatalf("wrong scope skip counts: scoped=%+v unscoped=%+v", scoped.DNS.captureStats(), unscoped.DNS.captureStats())
	}
	if len(scoped.DNS.records) != 2 || len(unscoped.DNS.records) != 3 {
		t.Fatalf("no-CIDR decoder behavior changed: scoped=%d unscoped=%d", len(scoped.DNS.records), len(unscoped.DNS.records))
	}
}

func TestMDNSCaptureCacheScopeKeepsWithdrawalAndBothBudgets(t *testing.T) {
	allow, err := ParseCaptureCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	inside := scopeTestAddress("inside.local.", [4]byte{10, 1, 2, 3}, 120)
	outside := scopeTestAddress("outside.local.", [4]byte{192, 0, 2, 1}, 120)
	decoder := newCaptureFrameDecoder(false)
	if decoder.DNS.observe("scope", outside, at) {
		t.Fatal("unscoped decoder rejected supported address")
	}
	decoder.DNS.allowedAddresses = allow // Model a scope change to test withdrawal ordering.
	outside.Header.TTL = 0
	if decoder.DNS.observe("scope", outside, at.Add(time.Second)) || len(decoder.DNS.records) != 0 {
		t.Fatal("out-of-scope goodbye failed to withdraw an existing record")
	}
	for i := 0; i < dnsCacheMaxRecords; i++ {
		if decoder.DNS.observe("scope", scopeTestAddress(fmt.Sprintf("inside-%d.local.", i), [4]byte{10, 1, 2, 3}, 600), at) {
			t.Fatalf("in-scope cache filled early at %d", i)
		}
	}
	if !decoder.DNS.observe("scope", inside, at) {
		t.Fatal("in-scope record escaped the entry limit")
	}
	if decoder.DNS.captureStats().SkippedOutOfScope.A != 0 {
		t.Fatal("in-scope capacity failure counted as scope skip")
	}
	byteDecoder := newCaptureFrameDecoder(false, allow...)
	byteDecoder.DNS.bytes = dnsCacheMaxBytes - 1
	if !byteDecoder.DNS.observe("scope", inside, at) {
		t.Fatal("in-scope record escaped the byte limit")
	}
	if byteDecoder.DNS.observe("scope", scopeTestAddress("outside.local.", [4]byte{192, 0, 2, 1}, 120), at) {
		t.Fatal("out-of-scope address was mistaken for byte-limit failure")
	}
	if byteDecoder.DNS.captureStats().SkippedOutOfScope.A != 1 {
		t.Fatal("out-of-scope byte-budget skip was not recorded")
	}
}

func BenchmarkMDNSCacheScopeAdmission(b *testing.B) {
	allow, err := ParseCaptureCIDRs("10.0.0.0/8")
	if err != nil {
		b.Fatal(err)
	}
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		allow  bool
		record dnsmessage.Resource
	}{
		{"unscoped_renew", false, scopeTestAddress("inside.local.", [4]byte{10, 1, 2, 3}, 120)},
		{"scoped_renew", true, scopeTestAddress("inside.local.", [4]byte{10, 1, 2, 3}, 120)},
		{"scoped_skip", true, scopeTestAddress("outside.local.", [4]byte{192, 0, 2, 3}, 120)},
	} {
		b.Run(test.name, func(b *testing.B) {
			var decoder *FrameDecoder
			if test.allow {
				decoder = newCaptureFrameDecoder(false, allow...)
			} else {
				decoder = newCaptureFrameDecoder(false)
			}
			decoder.DNS.observe("scope", test.record, at)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.DNS.observe("scope", test.record, at)
			}
		})
	}
}
