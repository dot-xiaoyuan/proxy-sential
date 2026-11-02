package store

import (
	"sync"
	"time"
)

const (
	streamBodyCacheTTL        = 30 * time.Second
	streamBodyCacheMaxBytes   = 4 << 20
	streamBodyCacheMaxEntry   = 64 << 10
	streamBodyCacheMaxEntries = 256
)

type verifiedStreamBody struct {
	body      []byte
	expiresAt time.Time
}

// The cache holds only global capture-coverage bytes whose exact reference and
// SHA-256 were checked against ClickHouse. Metadata is still read on every
// lookup, and case evidence bypasses this cache to read the archive directly.
type verifiedStreamBodyCache struct {
	mu      sync.Mutex
	entries map[StreamBodyRef]verifiedStreamBody
	bytes   int
}

func (c *verifiedStreamBodyCache) get(ref StreamBodyRef, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[ref]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, ref)
		c.bytes -= len(entry.body)
		return nil, false
	}
	return append([]byte(nil), entry.body...), true
}

func (c *verifiedStreamBodyCache) put(ref StreamBodyRef, body []byte, now time.Time) {
	if len(body) == 0 || len(body) > streamBodyCacheMaxEntry {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[StreamBodyRef]verifiedStreamBody)
	}
	if prior, ok := c.entries[ref]; ok {
		c.bytes -= len(prior.body)
		delete(c.entries, ref)
	}
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			c.bytes -= len(entry.body)
			delete(c.entries, key)
		}
	}
	if len(c.entries) >= streamBodyCacheMaxEntries || c.bytes+len(body) > streamBodyCacheMaxBytes {
		c.entries = make(map[StreamBodyRef]verifiedStreamBody)
		c.bytes = 0
	}
	c.entries[ref] = verifiedStreamBody{body: append([]byte(nil), body...), expiresAt: now.Add(streamBodyCacheTTL)}
	c.bytes += len(body)
}
