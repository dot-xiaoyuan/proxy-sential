package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"golang.org/x/net/dns/dnsmessage"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

// Decoder and fact-key behavior must evolve together for host announcements.
func TestMDNSHostAddressOnlyAnnouncementKeepsScopedWeakEvidence(t *testing.T) {
	at := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	a := coverageDNSAddress("Office-Laptop.local.", 120)
	var ip6 [16]byte
	copy(ip6[:], net.ParseIP("fd00::1234").To16())
	aaaa := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: a.Header.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AAAAResource{AAAA: ip6}}
	var decoder FrameDecoder
	events := decoder.Decode(coverageMDNSFrame(t, a, aaaa), source, at)
	if len(events) != 2 {
		t.Fatalf("A/AAAA-only host announcement lost: %d events", len(events))
	}
	for _, event := range events {
		if event.Type != "discovery" || event.SourceEventType != "dns_sd" || event.Subject["mac"] != "" || event.Observer["sensor_id"] != source.Node || event.Subject["site"] != source.Site || event.Subject["domain"] != source.Domain {
			t.Fatalf("unsafe or unscoped announcement: %+v", event)
		}
		if str(event.Payload, "dns_record_kind") != "host_address" || str(event.Payload, "dns_name") != "Office-Laptop.local." || str(event.Payload, "announcer_ip") != "10.1.2.99" {
			t.Fatalf("source DNS evidence absent: %+v", event.Payload)
		}
		for _, field := range []string{"service_type", "service_port", "service_instance", "service_target"} {
			if _, exists := event.Payload[field]; exists {
				t.Fatalf("host announcement invented %s", field)
			}
		}
		_, _, observation, err := StreamFactIdentity(event)
		if err != nil || observation.Name == "" || observation.Confidence != "clue" || observation.MAC != "" || observation.Evidence.Payload["address_binding"] == true || !strings.Contains(observation.Explanation, "主机名") {
			t.Fatalf("host weak evidence not expressible: %+v %v", observation, err)
		}
		if kind, _ := observationIoTType(observation); kind != "" {
			t.Fatal("hostname promoted to confirmed device type")
		}
	}
}

func mdnsHostContractEvent(name, recordType, ip string, ttl int, at time.Time) normalized.Event {
	return normalized.Event{SchemaVersion: "v1", EventID: "host-evidence", Type: "discovery", Source: "passive", SourceEventType: "dns_sd", Timestamp: at.Format(time.RFC3339Nano),
		Observer: map[string]any{"source_id": "mirror", "sensor_id": "sensor", "interface": "mirror0"}, Subject: map[string]any{"site": "campus", "domain": "access", "vlan": "100", "ip": ip},
		Payload: map[string]any{"origin": "dns_sd", "dns_record_kind": "host_address", "dns_name": name, "dns_record_type": recordType, "name": name, "is_response": true, "announcer_ip": "10.1.2.99", "ttl": ttl, "address_binding": false}, Confidence: 0.5}
}

func TestMDNSHostFactIdentitySeparatesAliasesAndKeepsWithdrawals(t *testing.T) {
	at := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	first := mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 120, at)
	alias := mdnsHostContractEvent("alias.local.", "A", "10.1.2.3", 120, at)
	device, fact, observation, err := StreamFactIdentity(first)
	if err != nil {
		t.Fatal(err)
	}
	aliasDevice, aliasFact, _, err := StreamFactIdentity(alias)
	if err != nil || device != aliasDevice || fact == aliasFact {
		t.Fatalf("separate DNS owner facts collapse: first=%s alias=%s error=%v", fact, aliasFact, err)
	}
	withdrawal := mdnsHostContractEvent("OFFICE.local.", "A", "10.1.2.3", 0, at.Add(time.Second))
	withdrawDevice, withdrawFact, withdrawn, err := StreamFactIdentity(withdrawal)
	if err != nil || withdrawDevice != device || withdrawFact != fact || !withdrawn.Withdrawn {
		t.Fatalf("withdrawal does not address the original fact: %+v %v", withdrawn, err)
	}
	if !observation.Current(at.Add(119*time.Second)) || observation.Current(at.Add(120*time.Second)) {
		t.Fatal("host fact did not honor its original record TTL")
	}
}

func TestMDNSHostCaptureRequiresAdvertisedAndAnnouncerAddressScope(t *testing.T) {
	at := time.Now()
	allow, err := ParseCaptureCIDRs("10.1.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	inside := mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 120, at)
	if got := filterCaptureEvents([]normalized.Event{inside}, allow); len(got) != 1 {
		t.Fatal("in-scope source and advertised address rejected")
	}
	outside := mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 120, at)
	outside.Payload["announcer_ip"] = "192.168.10.1"
	if got := filterCaptureEvents([]normalized.Event{outside}, allow); len(got) != 0 {
		t.Fatal("out-of-scope announcer admitted a host fact")
	}
}

func TestMDNSHostQueryDoesNotBecomeDeviceEvidence(t *testing.T) {
	frame := coverageMDNSFrame(t, coverageDNSAddress("queried.local.", 120))
	// Clear the DNS response bit while retaining the record-shaped payload.
	flags := binary.BigEndian.Uint16(frame[44:46])
	binary.BigEndian.PutUint16(frame[44:46], flags & ^uint16(0x8000))
	var decoder FrameDecoder
	if got := decoder.Decode(frame, Source{ID: "mirror"}, time.Now()); len(got) != 0 {
		t.Fatal("query promoted to host observation")
	}
}

func TestMDNSHostMessageEventLimitRecordsExactCoverageGap(t *testing.T) {
	records := make([]dnsmessage.Resource, 300)
	for i := range records {
		records[i] = coverageDNSAddress(fmt.Sprintf("host-%03d.local.", i), 120)
	}
	var decoder FrameDecoder
	frame := coverageMDNSFrame(t, records...)
	events := decoder.Decode(frame, Source{ID: "mirror"}, time.Now())
	assertMDNSOutputBound(t, events)
	if len(events) != maxMDNSMessageEvents {
		t.Fatalf("got %d bounded events", len(events))
	}
	coverage, _ := events[0].Payload["dns_message_coverage"].(map[string]any)
	if number(coverage, "candidate_events") != 300 || number(coverage, "emitted_events") != 250 || number(coverage, "omitted_events") != 50 || coverage["complete"] != false || len(str(events[0].Payload, "dns_message_sha256")) != 64 {
		t.Fatalf("incomplete coverage hidden: %+v", coverage)
	}
	observation, err := FromEvent(events[0])
	if err != nil || !strings.Contains(observation.Explanation, "未完整覆盖") {
		t.Fatalf("coverage gap absent from explanation: %+v %v", observation, err)
	}
}

func assertMDNSOutputBound(t *testing.T, events []normalized.Event) {
	t.Helper()
	if len(events) == 0 || len(events) > maxMDNSMessageEvents {
		t.Fatalf("unbounded or silent output: %d", len(events))
	}
	bytes := 0
	for _, event := range events {
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		bytes += len(raw)
	}
	if bytes > maxMDNSMessageEventBytes {
		t.Fatalf("message events exceed byte budget: %d", bytes)
	}
}

func TestMDNSCachedServiceFanoutRespectsMessageByteBudget(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror"}
	at := time.Now()
	for i := 0; i < 24; i++ {
		name := dnsmessage.MustNewName(fmt.Sprintf("printer-%02d._ipp._tcp.local.", i))
		srv := coverageDNSSRV(120)
		srv.Header.Name = name
		values := make([]string, 128)
		for j := range values {
			values[j] = strings.Repeat("x", 255)
		}
		txt := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: values}}
		decoder.Decode(coverageMDNSFrame(t, srv, txt, coverageDNSAddress("printer.local.", 120)), source, at)
	}
	events := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 120)), source, at.Add(time.Second))
	assertMDNSOutputBound(t, events)
	coverage, _ := events[0].Payload["dns_message_coverage"].(map[string]any)
	if len(events) >= 24 || number(coverage, "candidate_events") != 24 || number(coverage, "omitted_events") != 24-len(events) {
		t.Fatalf("service byte fanout unaccounted: emitted=%d coverage=%+v", len(events), coverage)
	}
}

func TestMDNSFirstOversizedTXTLeavesBoundedGapEvidence(t *testing.T) {
	event := streamDiscoveryEvent("service-evidence", time.Now().Format(time.RFC3339Nano), 120)
	event.Payload["txt"] = strings.Repeat("x", maxMDNSMessageEventBytes+1)
	output := mdnsOutput{messageHash: strings.Repeat("a", 64)}
	output.add(event)
	events := output.finish()
	assertMDNSOutputBound(t, events)
	coverage, _ := events[0].Payload["dns_message_coverage"].(map[string]any)
	if len(events) != 1 || number(coverage, "omitted_fields") != 1 || events[0].Payload["dns_fields_omitted"] == nil || events[0].Payload["txt"] != nil {
		t.Fatalf("oversized first TXT silently lost: %+v", events)
	}
	observation, err := FromEvent(events[0])
	if err != nil || observation.ModelName != "" || !strings.Contains(observation.Explanation, "未完整覆盖") {
		t.Fatalf("missing TXT promoted to product: %+v %v", observation, err)
	}
}

func TestMDNSHostScopeReplaySeparatesVLANAndPreservesSourceRecord(t *testing.T) {
	at := time.Now()
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	frame := coverageMDNSFrame(t, coverageDNSAddress("Office.local.", 120))
	var decoder FrameDecoder
	devices := map[string]bool{}
	for _, vlan := range []uint16{100, 200} {
		tag := []byte{0x81, 0, 0, 0}
		binary.BigEndian.PutUint16(tag[2:], vlan)
		tagged := append(append(append([]byte(nil), frame[:12]...), tag...), frame[12:]...)
		events := decoder.Decode(tagged, source, at)
		if len(events) != 1 || events[0].Subject["vlan"] != fmt.Sprint(vlan) || str(events[0].Payload, "dns_name") != "Office.local." || number(events[0].Payload, "dns_record_ttl") != 120 {
			t.Fatalf("DNS record/scope lost: %+v", events)
		}
		device, _, _, err := StreamFactIdentity(events[0])
		if err != nil || devices[device] {
			t.Fatalf("cross-VLAN host conflated: %s %v", device, err)
		}
		devices[device] = true
	}
}

func TestMDNSHostProjectionKeepsWeakCurrentStateAndEvidenceOnlyRenewal(t *testing.T) {
	at := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	first := mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 120, at)
	first.Observer["capture_scope_id"] = "scope-100"
	first.Payload["dns_message_sha256"] = strings.Repeat("a", 64)
	first.Payload["dns_message_id"] = 1
	first.Payload["dns_record_ttl"] = 120
	second := mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 300, at.Add(time.Second))
	second.EventID = "host-renewal"
	second.Observer["capture_scope_id"] = "scope-100"
	second.Payload["dns_message_sha256"] = strings.Repeat("b", 64)
	second.Payload["dns_message_id"] = 2
	second.Payload["dns_record_ttl"] = 300
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "host-replay", Source: "passive-discovery", AcceptedAt: at, Events: []normalized.Event{first, second}})
	if err != nil || len(prepared) != 2 || !prepared[0].HasFact || !prepared[1].HasFact {
		t.Fatalf("host projection failed: %+v %v", prepared, err)
	}
	if prepared[0].Fact.SemanticHash != prepared[1].Fact.SemanticHash {
		t.Fatal("message provenance or TTL changed host semantic content")
	}
	state, err := buildStreamDiscoveryState("host-replay", prepared[0].Fact.Device, []streamDiscoveryFact{prepared[0].Fact}, nil, at.Add(time.Second))
	if err != nil || state.Document["current"] != true || state.Document["primary_ip"] != "" || state.Document["mac"] != "" || state.Document["last_observed_ip"] != "10.1.2.3" || state.ClassificationStatus != "candidate" {
		t.Fatalf("host clue became a confirmed address binding: %+v %v", state, err)
	}
	if state, err = buildStreamDiscoveryState("host-replay", prepared[0].Fact.Device, []streamDiscoveryFact{prepared[0].Fact}, nil, at.Add(120*time.Second)); err != nil || state.Document["current"] != false {
		t.Fatalf("expired host clue stayed current: %+v %v", state, err)
	}
}

func TestMDNSHostCacheCannotRefreshOldHostEvidenceAndWithdrawalIgnoresCase(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Now()
	first := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("Office.local.", 120)), source, at)
	if len(first) != 1 {
		t.Fatal("host address not decoded")
	}
	txt := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("Office.local."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"note=present"}}}
	if got := decoder.Decode(coverageMDNSFrame(t, txt), source, at.Add(time.Second)); len(got) != 0 {
		t.Fatalf("cache generated a fresh host address from a TXT-only message: %+v", got)
	}
	withdrawal := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("OFFICE.local.", 0)), source, at.Add(2*time.Second))
	if len(withdrawal) != 1 || number(withdrawal[0].Payload, "ttl") != 0 {
		t.Fatal("case-variant withdrawal lost")
	}
	_, firstKey, _, _ := StreamFactIdentity(first[0])
	_, withdrawnKey, _, _ := StreamFactIdentity(withdrawal[0])
	if firstKey != withdrawnKey || len(decoder.DNS.records) != 1 {
		t.Fatal("case-variant withdrawal did not remove the original address")
	}
}

func TestMDNSHostLegacyWithdrawalUsesDNSOwnerAndCompleteScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	event := mdnsHostContractEvent("OFFICE.local.", "A", "10.1.2.3", 0, at)
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO discovery_snapshots").WithArgs("snapshot", "mirror", 1, at, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("(?s)UPDATE discovery_observations.*dns_record_kind.*dns_name.*dns_record_type.*node.*site.*domain.*vlan.*vrf.*interface.*announcer_ip").
		WithArgs(at, "mirror", "office.local", "A", "10.1.2.3", "sensor", "campus", "access", "100", "", "mirror0", "10.1.2.99").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO discovery_observations").WithArgs(event.EventID, sqlmock.AnyArg(), "mirror", "dns_sd", at, at, true, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (Repository{DB: db}).SaveSnapshot(context.Background(), Snapshot{ID: "snapshot", SourceID: "mirror", ConfigVersion: 1, At: at, Events: []normalized.Event{event}}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMDNSHostCannotPromoteAttachedProductFields(t *testing.T) {
	event := mdnsHostContractEvent("HP-LaserJet.local.", "A", "10.1.2.3", 120, time.Now())
	event.Payload["product_verified"] = true
	event.Payload["product_type"] = "printer"
	event.Payload["product_model"] = "HP LaserJet"
	observation, err := FromEvent(event)
	if err != nil || observation.DeviceType != "" || observation.ModelName != "" || len(streamRecognitionFields(observation)) != 0 {
		t.Fatalf("host announcement promoted to product evidence: %+v %v", observation, err)
	}
	if kind, _ := observationIoTType(observation); kind != "" {
		t.Fatal("host announcement promoted by downstream IoT classification")
	}
}

func TestMDNSFullCacheRetainsCurrentPacketResolutionAndReportsCapacity(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Now()
	for i := 0; i < dnsCacheMaxRecords; i++ {
		decoder.DNS.observe("mirror|campus|access||", coverageDNSAddress(fmt.Sprintf("cached-%d.local.", i), 600), at)
	}
	bytesBefore := decoder.DNS.bytes
	events := decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120), coverageDNSAddress("printer.local.", 120)), source, at)
	if len(events) != 1 || str(events[0].Payload, "service_type") != "_ipp._tcp" || str(events[0].Subject, "ip") != "10.1.2.3" {
		t.Fatalf("full cache discarded current-packet service resolution: %+v", events)
	}
	coverage, _ := events[0].Payload["dns_message_coverage"].(map[string]any)
	if number(coverage, "cache_records_not_retained") != 2 || coverage["complete"] != true || len(str(events[0].Payload, "dns_message_sha256")) != 64 {
		t.Fatalf("cache association gap is not explicit: %+v", events[0].Payload)
	}
	observation, err := FromEvent(events[0])
	if err != nil || strings.Contains(observation.Explanation, "关联缓存") || strings.Contains(observation.Explanation, "未完整覆盖") {
		t.Fatalf("cache pressure misrepresented current-message coverage: %+v %v", observation, err)
	}
	if len(decoder.DNS.records) != dnsCacheMaxRecords || decoder.DNS.bytes != bytesBefore {
		t.Fatal("current-packet fallback enlarged the retained cache")
	}
	assertMDNSOutputBound(t, events)
}

func TestMDNSCachePressureWithoutDeviceEventRemainsInCaptureStats(t *testing.T) {
	var decoder FrameDecoder
	at := time.Now()
	for i := 0; i < dnsCacheMaxRecords; i++ {
		decoder.DNS.observe("scope|", coverageDNSAddress(fmt.Sprintf("cached-%d.local.", i), 600), at)
	}
	source := Source{ID: "mirror", Address: "mirror0"}
	txt := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("service._ipp._tcp.local."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"note=present"}}}
	frame := coverageMDNSFrame(t, txt)
	for range 2 {
		if events := decoder.Decode(frame, source, at); len(events) != 0 {
			t.Fatalf("cache diagnostic invented a device: %+v", events)
		}
	}
	stats := NewCaptureStats()
	stats.DNSCache = decoder.DNS.captureStats()
	if stats.DNSCache.RecordsNotRetained != 2 || stats.DNSCache.MessagesWithRecordsNotRetained != 2 || stats.DNSCache.Records != dnsCacheMaxRecords || stats.DNSCache.Bytes > dnsCacheMaxBytes || len(stats.DNSCache.LastMessageSHA256) != 64 {
		t.Fatalf("unattributed cache pressure disappeared: %+v", stats.DNSCache)
	}
	snapshot := stats.snapshot()
	decoder.DNS.stats.RecordsNotRetained++
	stats.DNSCache = decoder.DNS.captureStats()
	if snapshot.DNSCache.RecordsNotRetained != 2 {
		t.Fatal("published cache diagnostics were mutated by capture")
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || !strings.Contains(string(raw), `"records_not_retained":2`) || !strings.Contains(string(raw), `"messages_with_records_not_retained":2`) {
		t.Fatalf("capture.stats omitted cache diagnostics: %s %v", raw, err)
	}
}

func TestMDNSHostJSONLFixturePreservesRecordEvidenceAndWithdrawsOnlyMatchingOwner(t *testing.T) {
	raw, err := os.ReadFile("../../examples/discovery/mdns-host-announcements.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var facts []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var event normalized.Event
		if err = json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		event, err = AdaptDiscoveryEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		_, key, observation, err := StreamFactIdentity(event)
		if err != nil || observation.MAC != "" || observation.DeviceType != "" || observation.Confidence != "clue" {
			t.Fatalf("fixture promoted to confirmed identity: %+v %v", observation, err)
		}
		facts = append(facts, key)
		header := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(str(event.Payload, "dns_name")), Class: dnsmessage.ClassINET, TTL: uint32(number(event.Payload, "dns_record_ttl"))}
		address := net.ParseIP(str(event.Subject, "ip"))
		var record dnsmessage.Resource
		if str(event.Payload, "dns_record_type") == "A" {
			header.Type = dnsmessage.TypeA
			body := &dnsmessage.AResource{}
			copy(body.A[:], address.To4())
			record = dnsmessage.Resource{Header: header, Body: body}
		} else {
			header.Type = dnsmessage.TypeAAAA
			body := &dnsmessage.AAAAResource{}
			copy(body.AAAA[:], address.To16())
			record = dnsmessage.Resource{Header: header, Body: body}
		}
		frame := coverageMDNSFrame(t, record)
		hash := sha256.Sum256(frame[42:])
		if str(event.Payload, "dns_message_sha256") != hex.EncodeToString(hash[:]) {
			t.Fatal("fixture hash does not match its reproducible original DNS message")
		}
	}
	if len(facts) != 4 || facts[0] == facts[1] || facts[0] == facts[2] || facts[0] != facts[3] {
		t.Fatalf("fixture collapsed DNS owners or record types: %+v", facts)
	}
}

func TestMDNSCacheAdmissionDiagnosticsDoNotChangeFacts(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, kind := range []string{"host", "service"} {
		t.Run(kind, func(t *testing.T) {
			events := make([]normalized.Event, 3)
			for i := range events {
				if kind == "host" {
					events[i] = mdnsHostContractEvent("office.local.", "A", "10.1.2.3", 120, at.Add(time.Duration(i)*time.Second))
				} else {
					events[i] = streamDiscoveryEvent(fmt.Sprint("service-", i), at.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano), 120)
				}
				events[i].EventID = fmt.Sprint("cache-pressure-", i)
				events[i].Observer["capture_scope_id"] = "scope-100"
			}
			events[1].Payload["dns_message_coverage"] = map[string]any{"candidate_events": 1, "emitted_events": 1, "omitted_events": 0, "complete": true, "cache_records_not_retained": 3}
			prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "cache-pressure-replay", Source: "passive-discovery", AcceptedAt: at, Events: events})
			if err != nil || len(prepared) != 3 {
				t.Fatalf("prepare: %+v %v", prepared, err)
			}
			for i := 1; i < len(prepared); i++ {
				decision := mergeStreamDiscoveryFact(&prepared[i-1].Fact, prepared[i].Fact)
				if decision.VisibleChanged || decision.Result != "repeat_observation" {
					t.Fatalf("cache pressure changed an unchanged %s fact: %+v", kind, decision)
				}
			}
			if events[1].Payload["dns_message_coverage"] == nil {
				t.Fatal("authoritative cache diagnostic removed")
			}
		})
	}
}

func TestMDNSSameMessageShortestTTLControlsCacheRegardlessOfOrder(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, ttls := range [][]uint32{{0, 120}, {120, 0}, {30, 120}, {120, 30}} {
		var decoder FrameDecoder
		events := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("office.local.", ttls[0]), coverageDNSAddress("office.local.", ttls[1])), Source{ID: "mirror"}, at)
		want := min(ttls[0], ttls[1])
		if len(events) != 1 || number(events[0].Payload, "ttl") != int(want) {
			t.Fatalf("inconsistent duplicate output: %v %+v", ttls, events)
		}
		if want == 0 && (len(decoder.DNS.records) != 0 || decoder.DNS.bytes != 0) {
			t.Fatalf("withdrawn duplicate retained: %v", ttls)
		}
		for _, entry := range decoder.DNS.records {
			if !entry.expires.Equal(at.Add(time.Duration(want) * time.Second)) {
				t.Fatalf("duplicate cache TTL differs from host: %v %+v", ttls, entry)
			}
		}
	}
}

func TestMDNSCanonicalRenewalRejectsByteGrowthBeforeMutating(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var cache DNSCache
	original := coverageDNSAddress("office.local.", 120)
	cache.observe("scope|", original, at)
	key := dnsCacheRecordKey("scope|", original)
	before := *cache.records[key]
	// Model capacity consumed by other entries without allocating 8 MiB of
	// unrelated evidence; this checks only the replacement reservation path.
	cache.bytes = dnsCacheMaxBytes
	if !cache.observe("scope|", coverageDNSAddress(" office.local.", 300), at.Add(time.Second)) {
		t.Fatal("renewal exceeded byte capacity")
	}
	after := cache.records[key]
	if cache.bytes != dnsCacheMaxBytes || after.bytes != before.bytes || !after.expires.Equal(before.expires) || after.record.Header.Name != before.record.Header.Name {
		t.Fatal("rejected renewal mutated retained evidence or expiry")
	}
}

func TestMDNSDuplicateIdentitySeparatesDNSClasses(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	inet := coverageDNSAddress("office.local.", 120)
	chaos := coverageDNSAddress("office.local.", 0)
	chaos.Header.Class = dnsmessage.Class(3)
	for _, records := range [][]dnsmessage.Resource{{inet, chaos}, {chaos, inet}} {
		var decoder FrameDecoder
		events := decoder.Decode(coverageMDNSFrame(t, records...), Source{ID: "mirror"}, at)
		if len(events) != 1 || number(events[0].Payload, "ttl") != 120 || len(decoder.DNS.records) != 1 {
			t.Fatalf("other DNS class withdrew INET address: events=%+v records=%+v", events, decoder.DNS.records)
		}
		for _, entry := range decoder.DNS.records {
			if entry.record.Header.Class&0x7fff != dnsmessage.ClassINET {
				t.Fatal("wrong class retained")
			}
		}
	}
}

func TestMDNSServiceProducerIDSeparatesSRVAttributes(t *testing.T) {
	for _, attribute := range []string{"priority", "weight"} {
		t.Run(attribute, func(t *testing.T) {
			var decoder FrameDecoder
			a, b := coverageDNSSRV(120), coverageDNSSRV(30)
			body := &dnsmessage.SRVResource{Port: 631, Target: dnsmessage.MustNewName("printer.local.")}
			if attribute == "priority" {
				body.Priority = 1
			} else {
				body.Weight = 1
			}
			b.Body = body
			events := decoder.Decode(coverageMDNSFrame(t, a, b, coverageDNSAddress("printer.local.", 120)), Source{ID: "mirror"}, time.Now())
			if len(events) != 2 {
				t.Fatalf("expected two SRV candidates: %+v", events)
			}
			if events[0].EventID == events[1].EventID {
				t.Fatalf("distinct outputs share producer ID %s, TTLs %v/%v", events[0].EventID, events[0].Payload["ttl"], events[1].Payload["ttl"])
			}
			_, firstFact, _, err1 := StreamFactIdentity(events[0])
			_, secondFact, _, err2 := StreamFactIdentity(events[1])
			if err1 != nil || err2 != nil || firstFact == secondFact {
				t.Fatalf("distinct SRV attributes collapsed facts: %s %s %v %v", firstFact, secondFact, err1, err2)
			}
		})
	}
}

func TestMDNSServiceSRVAttributesKeepRenewalAndWithdrawalFactIdentity(t *testing.T) {
	var decoder FrameDecoder
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	var originalDevice, originalFact string
	for index, ttl := range []uint32{120, 300, 0} {
		srv := coverageDNSSRV(ttl)
		srv.Body.(*dnsmessage.SRVResource).Priority = 2
		srv.Body.(*dnsmessage.SRVResource).Weight = 3
		events := decoder.Decode(coverageMDNSFrame(t, srv, coverageDNSAddress("printer.local.", 600)), source, at.Add(time.Duration(index)*time.Second))
		if len(events) != 1 {
			t.Fatalf("unexpected service output: %+v", events)
		}
		device, fact, observation, err := StreamFactIdentity(events[0])
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			originalDevice, originalFact = device, fact
		}
		if device != originalDevice || fact != originalFact || observation.Withdrawn != (ttl == 0) || number(events[0].Payload, "ttl") != int(ttl) {
			t.Fatalf("TTL lifecycle changed service identity: %+v", observation)
		}
	}
}

func TestMDNSHostWithdrawalCannotTargetAnotherAnnouncer(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Now()
	first := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("office.local.", 120)), source, at)[0]
	frame := coverageMDNSFrame(t, coverageDNSAddress("office.local.", 0))
	frame[29] = 100
	second := decoder.Decode(frame, source, at.Add(time.Second))[0]
	d1, f1, _, e1 := StreamFactIdentity(first)
	d2, f2, _, e2 := StreamFactIdentity(second)
	if e1 != nil || e2 != nil {
		t.Fatal(e1, e2)
	}
	if d1 != d2 || f1 == f2 {
		t.Fatalf("announcer %s goodbye targets fact from %s or creates a false address identity", second.Payload["announcer_ip"], first.Payload["announcer_ip"])
	}
	for _, event := range []normalized.Event{first, second} {
		event.Observer["capture_scope_id"] = "scope-100"
		if str(event.Subject, "mac") != "" || event.Payload["address_binding"] != false {
			t.Fatal("announcer isolation created an address binding")
		}
	}
	prepared, err := prepareStreamDiscovery(streamlog.Segment{Epoch: "announcer-review", Source: "passive-discovery", AcceptedAt: at, Events: []normalized.Event{first, second}})
	if err != nil || len(prepared) != 2 {
		t.Fatalf("prepare failed: %+v %v", prepared, err)
	}
	state, err := buildStreamDiscoveryState("announcer-review", prepared[0].Fact.Device, []streamDiscoveryFact{prepared[0].Fact, prepared[1].Fact}, nil, at.Add(2*time.Second))
	if err != nil || state.Document["current"] != true || state.Document["primary_ip"] != "" || state.Document["mac"] != "" {
		t.Fatalf("another announcer retired the original weak clue: %+v %v", state, err)
	}
}

func TestMDNSServiceFactIdentityUsesCompleteSRVRecord(t *testing.T) {
	base := streamDiscoveryEvent("srv", time.Now().Format(time.RFC3339Nano), 120)
	base.Payload["service_instance"], base.Payload["service_target"], base.Payload["service_port"] = "Printer._ipp._tcp.local.", "Printer.local.", 631
	_, original, _, err := StreamFactIdentity(base)
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]any{"service_target": "other.local.", "service_port": 632, "service_priority": 1, "service_weight": 1} {
		other := base
		other.Payload = cloneStreamFields(base.Payload)
		other.Payload[field] = value
		_, key, _, err := StreamFactIdentity(other)
		if err != nil || key == original {
			t.Fatalf("SRV identity ignored %s: %s %v", field, key, err)
		}
	}
	alias := base
	alias.Payload = cloneStreamFields(base.Payload)
	alias.Payload["service_instance"], alias.Payload["service_target"] = "PRINTER._IPP._TCP.LOCAL.", "PRINTER.LOCAL."
	alias.Payload["service_priority"], alias.Payload["service_weight"] = 0, 0
	_, key, _, err := StreamFactIdentity(alias)
	if err != nil || key != original {
		t.Fatal("DNS case or default zero priority/weight changed SRV identity")
	}
}

func TestMDNSServiceLegacyWithdrawalUsesCompleteSRVRecord(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	event := streamDiscoveryEvent("srv-goodbye", at.Format(time.RFC3339Nano), 0)
	event.Observer["interface"] = "mirror0"
	event.Subject["vlan"] = "100"
	event.Payload["service_target"], event.Payload["service_port"], event.Payload["service_priority"], event.Payload["service_weight"] = "Printer.local.", 631, 2, 3
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO discovery_snapshots").WithArgs("snapshot", "passive-a", 1, at, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("(?s)UPDATE discovery_observations.*service_target.*service_instance.*site.*domain.*vlan.*service_port.*service_priority.*service_weight.*node.*vrf.*interface").WithArgs(at, "passive-a", "printer.local", "printer-a", "site-a", "domain-a", "100", "631", "2", "3", "sensor-a", "", "mirror0").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO discovery_observations").WithArgs(event.EventID, sqlmock.AnyArg(), "passive-a", "dns_sd", at, at, true, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := (Repository{DB: db}).SaveSnapshot(context.Background(), Snapshot{ID: "snapshot", SourceID: "passive-a", ConfigVersion: 1, At: at, Events: []normalized.Event{event}}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
