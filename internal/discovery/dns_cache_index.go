package discovery

import (
	"container/heap"
	"encoding/json"
	"sort"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// These are capture-layer facts. VRF attribution belongs to the controlled
// capture scope applied later; it is never inferred from names or addresses.
// An announcing peer cannot complete another peer's cached service records.
func dnsCacheNamespace(source Source, vlan, announcer string) string {
	raw, _ := json.Marshal([7]string{source.ID, source.Node, source.Site, source.Domain, source.Address, vlan, announcer})
	return string(raw)
}

type dnsOwnerKey struct{ scope, owner string }
type dnsRecordIndex map[dnsOwnerKey]map[string]struct{}

func (index *dnsRecordIndex) add(owner dnsOwnerKey, key string) {
	if *index == nil {
		*index = make(dnsRecordIndex)
	}
	keys := (*index)[owner]
	if keys == nil {
		keys = make(map[string]struct{})
		(*index)[owner] = keys
	}
	keys[key] = struct{}{}
}

func (index dnsRecordIndex) remove(owner dnsOwnerKey, key string) {
	keys := index[owner]
	delete(keys, key)
	if len(keys) == 0 {
		delete(index, owner)
	}
}

// Each retained record owns exactly one heap slot and one owner membership.
// SRV/PTR records own one additional reverse membership. Renewals fix the
// existing heap slot; expiry/withdrawal removes all memberships and empty
// buckets. No stale expiry entries or names from failed admissions accumulate.
type dnsExpiryQueue []*cachedDNS

func (q dnsExpiryQueue) Len() int           { return len(q) }
func (q dnsExpiryQueue) Less(i, j int) bool { return q[i].expires.Before(q[j].expires) }
func (q dnsExpiryQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].expiryIndex, q[j].expiryIndex = i, j
}
func (q *dnsExpiryQueue) Push(value any) {
	entry := value.(*cachedDNS)
	entry.expiryIndex = len(*q)
	*q = append(*q, entry)
}
func (q *dnsExpiryQueue) Pop() any {
	last := len(*q) - 1
	entry := (*q)[last]
	(*q)[last] = nil
	*q = (*q)[:last]
	entry.expiryIndex = -1
	return entry
}

func (c *DNSCache) addIndexes(entry *cachedDNS) {
	c.byOwner.add(dnsOwnerKey{entry.scope, entry.owner}, entry.key)
	switch body := entry.record.Body.(type) {
	case *dnsmessage.SRVResource:
		entry.target = canonicalDNSOwner(body.Target.String())
		c.srvByTarget.add(dnsOwnerKey{entry.scope, entry.target}, entry.key)
	case *dnsmessage.PTRResource:
		entry.target = canonicalDNSOwner(body.PTR.String())
		c.ptrByTarget.add(dnsOwnerKey{entry.scope, entry.target}, entry.key)
	}
	heap.Push(&c.expiry, entry)
}

func (c *DNSCache) removeIndexes(entry *cachedDNS) {
	c.byOwner.remove(dnsOwnerKey{entry.scope, entry.owner}, entry.key)
	switch entry.record.Body.(type) {
	case *dnsmessage.SRVResource:
		c.srvByTarget.remove(dnsOwnerKey{entry.scope, entry.target}, entry.key)
	case *dnsmessage.PTRResource:
		c.ptrByTarget.remove(dnsOwnerKey{entry.scope, entry.target}, entry.key)
	}
	heap.Remove(&c.expiry, entry.expiryIndex)
}

func (c *DNSCache) refreshExpiry(entry *cachedDNS) {
	heap.Fix(&c.expiry, entry.expiryIndex)
}

func (c *DNSCache) expire(at time.Time) {
	for len(c.expiry) > 0 && !c.expiry[0].expires.After(at) {
		c.remove(c.expiry[0].key)
	}
}

// relatedRecords materializes the message and only service dependencies of
// its touched owners. An A-only message with no matching SRV does not read the
// rest of the cache. Shared service targets are expanded once, not per SRV.
func (c *DNSCache) relatedRecords(scope string, current []dnsmessage.Resource, touched map[string]bool, at time.Time) []dnsmessage.Resource {
	services := make(map[string]dnsmessage.Resource)
	for _, record := range current {
		if _, ok := record.Body.(*dnsmessage.SRVResource); ok {
			services[dnsCacheRecordKey(scope, record)] = record
		}
	}
	live := func(entry *cachedDNS) bool {
		return entry != nil && !entry.at.After(at) && entry.expires.After(at)
	}
	addService := func(key string) {
		if _, currentWins := services[key]; currentWins {
			return
		}
		entry := c.records[key]
		if !live(entry) {
			return
		}
		if _, ok := entry.record.Body.(*dnsmessage.SRVResource); ok {
			services[key] = entry.record
		}
	}
	for name := range touched {
		owner := dnsOwnerKey{scope, canonicalDNSOwner(name)}
		for key := range c.byOwner[owner] {
			addService(key)
		}
		for key := range c.srvByTarget[owner] {
			addService(key)
		}
	}
	if len(services) == 0 {
		return current
	}

	const needAddress, needTXT = 1, 2
	owners := make(map[string]int)
	instances := make(map[string]struct{})
	for _, record := range services {
		owner := canonicalDNSOwner(record.Header.Name.String())
		target := canonicalDNSOwner(record.Body.(*dnsmessage.SRVResource).Target.String())
		owners[owner] |= needTXT
		owners[target] |= needAddress
		instances[owner] = struct{}{}
	}
	currentKeys := make(map[string]struct{}, len(current))
	for _, record := range current {
		currentKeys[dnsCacheRecordKey(scope, record)] = struct{}{}
	}
	selected := make(map[string]*cachedDNS)
	addCached := func(key string) {
		if _, exists := currentKeys[key]; !exists && live(c.records[key]) {
			selected[key] = c.records[key]
		}
	}
	for key := range services {
		addCached(key)
	}
	for name, needed := range owners {
		for key := range c.byOwner[dnsOwnerKey{scope, name}] {
			entry := c.records[key]
			switch entry.record.Body.(type) {
			case *dnsmessage.AResource, *dnsmessage.AAAAResource:
				if needed&needAddress != 0 {
					addCached(key)
				}
			case *dnsmessage.TXTResource:
				if needed&needTXT != 0 {
					addCached(key)
				}
			}
		}
	}
	for name := range instances {
		for key := range c.ptrByTarget[dnsOwnerKey{scope, name}] {
			addCached(key)
		}
	}
	entries := make([]*cachedDNS, 0, len(selected))
	for _, entry := range selected {
		entries = append(entries, entry)
	}
	// Newer cached TXT/PTR values win deterministic map assignment below;
	// current-message values follow them and retain their original TTL.
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].at.Equal(entries[j].at) {
			return entries[i].at.Before(entries[j].at)
		}
		return entries[i].key < entries[j].key
	})
	records := make([]dnsmessage.Resource, 0, len(entries)+len(current))
	for _, entry := range entries {
		record := entry.record
		record.Header.TTL = uint32(entry.expires.Sub(at) / time.Second)
		records = append(records, record)
	}
	return append(records, current...)
}
