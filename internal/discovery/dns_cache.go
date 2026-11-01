package discovery

import (
	"fmt"
	"strconv"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsCacheMaxRecords = 10000
const dnsCacheMaxBytes = 8 << 20

type dnsCacheAdmissionFailure uint8

const (
	dnsCacheAdmitted dnsCacheAdmissionFailure = iota
	dnsCacheRecordLimit
	dnsCacheByteLimit
)

// Count only the five RR kinds that can occupy the cache. Fixed fields avoid
// allocating a map or accepting unbounded label values on the capture path.
func (c *DNSCache) countAdmissionFailure(record dnsmessage.Resource, reason dnsCacheAdmissionFailure) {
	var counts *DNSCacheRecordKinds
	switch reason {
	case dnsCacheRecordLimit:
		counts = &c.stats.NotRetainedByRecordLimit
	case dnsCacheByteLimit:
		counts = &c.stats.NotRetainedByByteLimit
	default:
		return
	}
	switch record.Body.(type) {
	case *dnsmessage.AResource:
		counts.A++
	case *dnsmessage.AAAAResource:
		counts.AAAA++
	case *dnsmessage.PTRResource:
		counts.PTR++
	case *dnsmessage.SRVResource:
		counts.SRV++
	case *dnsmessage.TXTResource:
		counts.TXT++
	}
}

func (c *DNSCache) remove(key string) {
	if old, ok := c.records[key]; ok {
		c.removeIndexes(old)
		c.bytes -= old.bytes
		delete(c.records, key)
	}
}

func dnsCacheRecordKey(scope string, record dnsmessage.Resource) string {
	bodyKey := fmt.Sprint(record.Body)
	switch body := record.Body.(type) {
	case *dnsmessage.PTRResource:
		bodyKey = canonicalDNSOwner(body.PTR.String())
	case *dnsmessage.SRVResource:
		bodyKey = fmt.Sprint(body.Priority, ":", body.Weight, ":", body.Port, ":", canonicalDNSOwner(body.Target.String()))
	}
	return scope + strconv.Quote(canonicalDNSOwner(record.Header.Name.String())) + "|" + fmt.Sprint(record.Header.Class&0x7fff) + "|" + fmt.Sprint(record.Header.Type) + "|" + bodyKey
}

// mdnsMessageRecords resolves duplicate RRs before either cache mutation or
// current-message service resolution. A goodbye/shorter validity in the same
// message wins regardless of record order, matching the standalone host path.
func mdnsMessageRecords(records []dnsmessage.Resource) []dnsmessage.Resource {
	selected := make([]dnsmessage.Resource, 0, len(records))
	positions := make(map[string]int, len(records))
	for _, record := range records {
		key := dnsCacheRecordKey("", record)
		if index, found := positions[key]; found {
			if record.Header.TTL < selected[index].Header.TTL {
				selected[index] = record
			}
			continue
		}
		positions[key] = len(selected)
		selected = append(selected, record)
	}
	return selected
}

// observe reports only supported records rejected by the retained cache budget.
// Callers can still resolve the current message without retaining those records.
func (c *DNSCache) observe(scope string, record dnsmessage.Resource, at time.Time) bool {
	return c.observeAdmission(scope, record, at) != dnsCacheAdmitted
}

func (c *DNSCache) observeAdmission(scope string, record dnsmessage.Resource, at time.Time) dnsCacheAdmissionFailure {
	key := dnsCacheRecordKey(scope, record)
	if record.Header.TTL == 0 {
		c.remove(key)
		return dnsCacheAdmitted
	}
	ttl := min(record.Header.TTL, discoveryMaxTTLSeconds)
	size := dnsCacheEntryBytes(key, record)
	if size == 0 {
		return dnsCacheAdmitted
	}
	if old, exists := c.records[key]; exists {
		// Canonical names can share a key while retaining different wire
		// lengths. Charge the replacement delta before changing its lifetime.
		if size-old.bytes > dnsCacheMaxBytes-c.bytes {
			return dnsCacheByteLimit
		}
		c.bytes += size - old.bytes
		old.bytes = size
		old.record, old.at, old.expires = record, at, at.Add(time.Duration(ttl)*time.Second)
		c.refreshExpiry(old)
		return dnsCacheAdmitted
	}
	// Preserve the existing first-failed-gate order when both limits are hit.
	if len(c.records) >= dnsCacheMaxRecords {
		return dnsCacheRecordLimit
	}
	if size > dnsCacheMaxBytes-c.bytes {
		return dnsCacheByteLimit
	}
	if c.records == nil {
		c.records = make(map[string]*cachedDNS)
	}
	entry := &cachedDNS{record: record, expires: at.Add(time.Duration(ttl) * time.Second), at: at, bytes: size, key: key, scope: scope, owner: canonicalDNSOwner(record.Header.Name.String()), expiryIndex: -1}
	c.records[key] = entry
	c.addIndexes(entry)
	c.bytes += size
	return dnsCacheAdmitted
}

// Charge retained key bytes plus the expanded DNS wire-record size. This is a
// payload budget, not a claim about process RSS; the independent record limit
// also bounds map/Go object overhead. Only records used by service resolution
// occupy the cache. In particular, unrelated large unknown RRs cannot evict
// the supported address and service records by exhausting the record budget.
func dnsCacheEntryBytes(key string, record dnsmessage.Resource) int {
	if record.Header.Class&0x7fff != dnsmessage.ClassINET {
		return 0
	}
	nameBytes := func(name dnsmessage.Name) int {
		if name.Length == 1 { // root name
			return 1
		}
		return int(name.Length) + 1
	}
	size := len(key) + nameBytes(record.Header.Name) + 10
	switch body := record.Body.(type) {
	case *dnsmessage.AResource:
		return size + 4
	case *dnsmessage.AAAAResource:
		return size + 16
	case *dnsmessage.PTRResource:
		return size + nameBytes(body.PTR)
	case *dnsmessage.SRVResource:
		return size + 6 + nameBytes(body.Target)
	case *dnsmessage.TXTResource:
		for _, text := range body.TXT {
			size += 1 + len(text)
		}
		return size
	default:
		return 0
	}
}

func (c *DNSCache) captureStats() DNSCacheCaptureStats {
	snapshot := c.stats
	snapshot.Records, snapshot.Bytes = len(c.records), c.bytes
	return snapshot
}
