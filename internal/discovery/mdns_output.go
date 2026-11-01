package discovery

import (
	"encoding/json"
	"net"
	"sort"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"proxy-sentinel/internal/normalized"
)

const maxMDNSMessageEvents = 250
const maxMDNSMessageEventBytes = 512 << 10

// The record and message hash identify a coverage gap without preserving a
// second packet-body copy. Reserve space for the optional coverage annotation
// on each emitted event before accepting it into the output budget.
const mdnsCoverageReserveBytes = 512

type mdnsOutput struct {
	events           []normalized.Event
	bytes            int
	candidates       int
	omitted          int
	omittedFields    int
	cacheNotRetained int
	sealed           bool
	messageHash      string
}

func (b *mdnsOutput) omit(count int) {
	b.candidates += count
	b.omitted += count
}

func (b *mdnsOutput) add(event normalized.Event) {
	b.candidates++
	if b.sealed || len(b.events) == maxMDNSMessageEvents {
		b.sealed = true
		b.omitted++
		return
	}
	raw, _ := json.Marshal(event) // Decoder values are JSON primitives only.
	size := len(raw) + mdnsCoverageReserveBytes
	if size > maxMDNSMessageEventBytes-b.bytes {
		if len(b.events) == 0 {
			// A huge TXT must leave a bounded gap record even if it is the
			// first candidate. Keep its real service/address identity and TTL,
			// but do not promote the omitted product fields into classification.
			delete(event.Payload, "txt")
			event.Payload["dns_fields_omitted"] = []string{"txt"}
			b.omittedFields++
			raw, _ = json.Marshal(event)
			size = len(raw) + mdnsCoverageReserveBytes
			// All remaining fields originate from bounded DNS names, ports,
			// addresses and the controlled source identity.
		} else {
			b.omitted++
			b.sealed = true
			return
		}
	}
	b.events = append(b.events, event)
	b.bytes += size
}

func (b *mdnsOutput) finish() []normalized.Event {
	if b.omitted == 0 && b.omittedFields == 0 && b.cacheNotRetained == 0 {
		return b.events
	}
	for i := range b.events {
		b.events[i].Payload["dns_message_sha256"] = b.messageHash
		b.events[i].Payload["dns_message_coverage"] = map[string]any{
			"candidate_events": b.candidates, "emitted_events": len(b.events), "omitted_events": b.omitted,
			"omitted_fields": b.omittedFields, "event_limit": maxMDNSMessageEvents, "event_bytes_limit": maxMDNSMessageEventBytes,
			"complete": b.omitted == 0 && b.omittedFields == 0,
		}
		if b.cacheNotRetained > 0 {
			b.events[i].Payload["dns_message_coverage"].(map[string]any)["cache_records_not_retained"] = b.cacheNotRetained
		}
	}
	return b.events
}

type mdnsHostRecord struct {
	record dnsmessage.Resource
	ip     string
	kind   string
	key    string
}

// Only records actually present in this DNS message can create/renew a host
// fact. Cache-assisted service resolution must not refresh a stale host fact.
func mdnsHostRecords(records []dnsmessage.Resource, serviceTargets map[string]bool) []mdnsHostRecord {
	byKey := map[string]mdnsHostRecord{}
	for _, record := range records {
		if record.Header.Class&0x7fff != dnsmessage.ClassINET {
			continue
		}
		name := record.Header.Name.String()
		if canonicalDNSOwner(name) == "" || len(name) > 254 || strings.ContainsAny(name, "\x00\r\n") {
			continue
		}
		var ip net.IP
		kind := ""
		switch value := record.Body.(type) {
		case *dnsmessage.AResource:
			ip, kind = net.IP(value.A[:]), "A"
		case *dnsmessage.AAAAResource:
			ip, kind = net.IP(value.AAAA[:]), "AAAA"
		default:
			continue
		}
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || kind == "AAAA" && ip.To4() != nil {
			continue
		}
		// A resolved service already covers this address in the current
		// message. Withdrawals still retire any earlier standalone host fact.
		if record.Header.TTL != 0 && serviceTargets[strings.ToLower(name)] {
			continue
		}
		key := canonicalDNSOwner(name) + "|" + kind + "|" + ip.String()
		if previous, exists := byKey[key]; exists && previous.record.Header.TTL <= record.Header.TTL {
			continue // duplicate records take the shortest validity, including zero
		}
		byKey[key] = mdnsHostRecord{record: record, ip: ip.String(), kind: kind, key: key}
	}
	out := make([]mdnsHostRecord, 0, len(byKey))
	for _, record := range byKey {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// Cache admission and current-message output coverage are separate boundaries.
func mdnsCoverageExplanation(payload map[string]any) string {
	coverage, ok := payload["dns_message_coverage"].(map[string]any)
	if !ok {
		return ""
	}
	explanation := ""
	if number(coverage, "omitted_events") > 0 || number(coverage, "omitted_fields") > 0 {
		explanation += "；该 DNS 消息超出有界输出范围，未完整覆盖"
	}
	// Cache admission is collector health metadata, not device evidence.
	// Keep it in the authoritative event/stats without changing fact versions.
	return explanation
}
