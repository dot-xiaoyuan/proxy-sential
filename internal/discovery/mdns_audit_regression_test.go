package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestMDNSReviewCacheRenewalChargesChangedDNSWireLength(t *testing.T) {
	var cache DNSCache
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cache.observe("scope|", coverageDNSAddress("office.local.", 120), at)
	cache.observe("scope|", coverageDNSAddress(" office.local.", 300), at.Add(time.Second))
	charged := 0
	for key, entry := range cache.records {
		actual := dnsCacheEntryBytes(key, entry.record)
		if entry.bytes != actual {
			t.Errorf("renewal retained a different-sized record without recharging: stored=%d actual=%d", entry.bytes, actual)
		}
		charged += actual
	}
	if cache.bytes != charged {
		t.Fatalf("cache byte total differs from retained records: total=%d actual=%d", cache.bytes, charged)
	}
}

func TestMDNSReviewDuplicateGoodbyeCannotRemainInCache(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	events := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("office.local.", 0), coverageDNSAddress("office.local.", 120)), source, time.Now())
	if len(events) != 1 || number(events[0].Payload, "ttl") != 0 {
		t.Fatalf("duplicate host record did not retain shortest validity: %+v", events)
	}
	if len(decoder.DNS.records) != 0 || decoder.DNS.bytes != 0 {
		t.Fatalf("cache retained a host that this same message withdrew: count=%d bytes=%d", len(decoder.DNS.records), decoder.DNS.bytes)
	}
}

func TestMDNSReviewCoverageCountsDoNotChangeSemanticHash(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	first := mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 120, at)
	second := mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 120, at.Add(time.Second))
	second.EventID = "same-host-new-message"
	for _, event := range []normalized.Event{first, second} {
		event.Observer["capture_scope_id"] = "scope-100"
	}
	first.Payload["dns_message_coverage"] = map[string]any{"candidate_events": 350, "emitted_events": 250, "omitted_events": 100, "complete": false}
	second.Payload["dns_message_coverage"] = map[string]any{"candidate_events": 300, "emitted_events": 250, "omitted_events": 50, "complete": false}
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "coverage-replay", Source: "passive-discovery", AcceptedAt: at, Events: []normalized.Event{first, second}})
	if err != nil || len(prepared) != 2 || !prepared[0].HasFact || !prepared[1].HasFact {
		t.Fatalf("valid host evidence rejected: %+v %v", prepared, err)
	}
	if prepared[0].Fact.SemanticHash != prepared[1].Fact.SemanticHash {
		t.Fatal("message coverage counts changed an otherwise unchanged host fact semantic hash")
	}
}
