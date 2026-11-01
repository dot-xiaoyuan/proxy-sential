package discovery

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"proxy-sentinel/internal/normalized"
)

func coverageMDNSFrame(t *testing.T, records ...dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: records}
	body, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 42+len(body))
	copy(frame[6:12], []byte{2, 1, 2, 3, 4, 5})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(28+len(body)))
	frame[23] = 17
	copy(frame[26:30], []byte{10, 1, 2, 99})
	binary.BigEndian.PutUint16(frame[34:36], 5353)
	binary.BigEndian.PutUint16(frame[36:38], 5353)
	binary.BigEndian.PutUint16(frame[38:40], uint16(8+len(body)))
	copy(frame[42:], body)
	return frame
}

func coverageDNSAddress(name string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: [4]byte{10, 1, 2, 3}}}
}

func coverageDNSSRV(ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("Printer._ipp._tcp.local."), Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.SRVResource{Port: 631, Target: dnsmessage.MustNewName("printer.local.")}}
}

func TestMDNSFullCacheRefreshesExistingRecordsAndRetainsWithdrawal(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(2), coverageDNSAddress("printer.local.", 2)), source, at)
	for start := 0; start < 9998; start += 200 {
		records := make([]dnsmessage.Resource, 0, 200)
		for i := start; i < min(start+200, 9998); i++ {
			records = append(records, coverageDNSAddress(fmt.Sprintf("host-%d.local.", i), 600))
		}
		decoder.Decode(coverageMDNSFrame(t, records...), source, at)
	}
	if len(decoder.DNS.records) != 10000 {
		t.Fatalf("cache has %d records", len(decoder.DNS.records))
	}
	renewed := decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120), coverageDNSAddress("printer.local.", 120)), source, at.Add(time.Second))
	if len(renewed) != 1 || number(renewed[0].Payload, "ttl") != 120 || renewed[0].Subject["ip"] != "10.1.2.3" || renewed[0].Subject["mac"] != "" {
		t.Fatalf("full cache lost live renewal or attributed relay MAC: %+v", renewed)
	}
	decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("overflow.local.", 600)), source, at.Add(time.Second))
	if len(decoder.DNS.records) != 10000 {
		t.Fatal("new record exceeded cache capacity")
	}
	// Check after the original TTL, with no fresh address in this packet.
	current := decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120)), source, at.Add(3*time.Second))
	if len(current) != 1 || current[0].Subject["ip"] != "10.1.2.3" {
		t.Fatalf("renewed address expired at its old deadline: %+v", current)
	}
	withdrawn := decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("printer.local.", 0)), source, at.Add(4*time.Second))
	if len(withdrawn) != 2 || number(withdrawn[0].Payload, "ttl") != 0 || number(withdrawn[1].Payload, "ttl") != 0 || !isMDNSHostAnnouncement(withdrawn[1]) {
		t.Fatalf("address withdrawal disappeared: %+v", withdrawn)
	}
	if len(decoder.DNS.records) != 9999 {
		t.Fatal("withdrawn record retained cache capacity")
	}
	after := decoder.Decode(coverageMDNSFrame(t, coverageDNSSRV(120)), source, at.Add(5*time.Second))
	if len(after) != 1 || after[0].Subject["ip"] != "" {
		t.Fatalf("withdrawn address became current again: %+v", after)
	}
	decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("later.local.", 120)), source, at.Add(601*time.Second))
	if len(decoder.DNS.records) != 1 {
		t.Fatalf("expired records retained: %d", len(decoder.DNS.records))
	}
}

func coverageLLDPFrame(description string, management bool) []byte {
	frame := []byte{1, 0x80, 0xc2, 0, 0, 0x0e, 2, 1, 2, 3, 4, 5, 0x88, 0xcc}
	add := func(kind int, value []byte) {
		header := make([]byte, 2)
		binary.BigEndian.PutUint16(header, uint16(kind<<9|len(value)))
		frame = append(append(frame, header...), value...)
	}
	add(1, []byte{4, 2, 3, 4, 5, 6, 7})
	add(2, []byte{5, '1'})
	add(3, []byte{0, 120})
	add(5, []byte("edge-switch"))
	add(6, []byte(description))
	if management {
		add(8, []byte{5, 1, 10, 1, 2, 3, 2, 0, 0, 0, 1, 0})
	}
	add(0, nil)
	return frame
}

func TestLLDPDescriptionReachesStandardEventAndRecognition(t *testing.T) {
	description := "Campus switch model ABC-123"
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access", Address: "mirror0"}
	for _, management := range []bool{false, true} {
		events := DecodeFrame(coverageLLDPFrame(description, management), source, time.Now())
		if len(events) != 1 || str(events[0].Payload, "system_description") != description {
			t.Fatalf("description lost: %+v", events)
		}
		observation, err := FromEvent(events[0])
		if err != nil || streamRecognitionFields(observation)["lldp_system_description"] != description {
			t.Fatalf("description absent from recognition: %+v %v", observation, err)
		}
		wantIP := ""
		if management {
			wantIP = "10.1.2.3"
		}
		if observation.IP != wantIP || observation.MAC != "" || observation.Confidence != "clue" {
			t.Fatalf("neighbor identity overclaimed: %+v", observation)
		}
		allow, _ := ParseCaptureCIDRs("10.0.0.0/8")
		kept := filterCaptureEvents(append([]normalized.Event(nil), events...), allow)
		if len(kept) == 1 && !management {
			t.Fatal("description bypassed the existing IP capture boundary")
		}
	}
}

func TestMDNSCacheByteBudgetRenewalExpiryAndWithdrawal(t *testing.T) {
	var decoder FrameDecoder
	source := Source{ID: "mirror", Node: "sensor", Site: "campus", Domain: "access"}
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	largeTXT := func(index int, ttl uint32) dnsmessage.Resource {
		text := make([]string, 30)
		for i := range text {
			text[i] = strings.Repeat("x", 255)
		}
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(fmt.Sprintf("large-%d._ipp._tcp.local.", index)), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.TXTResource{TXT: text}}
	}
	for i := 0; i < dnsCacheMaxRecords; i++ {
		before := len(decoder.DNS.records)
		decoder.Decode(coverageMDNSFrame(t, largeTXT(i, 120)), source, at)
		if len(decoder.DNS.records) == before {
			break
		}
	}
	count, budget := len(decoder.DNS.records), decoder.DNS.bytes
	if count == 0 || count >= dnsCacheMaxRecords || budget > dnsCacheMaxBytes || budget < dnsCacheMaxBytes-20000 {
		t.Fatalf("independent byte budget not enforced: count=%d bytes=%d", count, budget)
	}
	decoder.Decode(coverageMDNSFrame(t, largeTXT(0, 300)), source, at.Add(60*time.Second))
	if decoder.DNS.bytes != budget || len(decoder.DNS.records) != count {
		t.Fatal("same-record renewal changed cache capacity")
	}
	decoder.Decode(coverageMDNSFrame(t, coverageDNSAddress("later.local.", 600)), source, at.Add(121*time.Second))
	if len(decoder.DNS.records) != 2 {
		t.Fatalf("expired entries retained or live renewal lost: %d", len(decoder.DNS.records))
	}
	decoder.Decode(coverageMDNSFrame(t, largeTXT(0, 0)), source, at.Add(122*time.Second))
	if len(decoder.DNS.records) != 1 || decoder.DNS.bytes <= 0 || decoder.DNS.bytes >= 1024 {
		t.Fatalf("withdrawal did not free its byte charge: %d/%d", len(decoder.DNS.records), decoder.DNS.bytes)
	}
	decoder.Decode(coverageMDNSFrame(t), source, at.Add(800*time.Second))
	if len(decoder.DNS.records) != 0 || decoder.DNS.bytes != 0 {
		t.Fatalf("expiration left capacity debt: %d/%d", len(decoder.DNS.records), decoder.DNS.bytes)
	}
}

func TestMDNSCacheDoesNotStoreUnrelatedResourceBodies(t *testing.T) {
	var decoder FrameDecoder
	rr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("unknown.local."), Type: 65000, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.UnknownResource{Type: 65000, Data: make([]byte, 60000)}}
	decoder.Decode(coverageMDNSFrame(t, rr), Source{ID: "mirror"}, time.Now())
	if len(decoder.DNS.records) != 0 || decoder.DNS.bytes != 0 {
		t.Fatal("unrelated records consumed the service-resolution cache")
	}
}

func TestLLDPUnsafeDescriptionRemainsEvidenceWithoutRecognitionField(t *testing.T) {
	description := "model\x00untrusted"
	events := DecodeFrame(coverageLLDPFrame(description, true), Source{ID: "mirror"}, time.Now())
	if len(events) != 1 || str(events[0].Payload, "system_description") != description {
		t.Fatal("original description was not retained")
	}
	observation, err := FromEvent(events[0])
	if err != nil || streamRecognitionFields(observation)["lldp_system_description"] != "" {
		t.Fatalf("unsafe description was promoted: %+v %v", observation, err)
	}
}
