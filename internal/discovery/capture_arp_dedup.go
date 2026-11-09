package discovery

import (
	"time"

	"proxy-sentinel/internal/normalized"
)

// arpDedupCache suppresses repeated ARP observations of an unchanged
// (source, sensor, MAC, IP) mapping inside a bounded window. The first
// observation, the first refresh after the window, and any address change
// still reach the durable stream; only exact repeats inside the window are
// dropped. This trims the capture volume produced by broadcast ARP floods
// without losing device bindings or change evidence.
type arpDedupCache struct {
	window    time.Duration
	now       func() time.Time
	last      map[string]time.Time
	macIP     map[string]string
	ipMAC     map[string]string
	nextSweep time.Time
}

func newARPDedupCache(window time.Duration) *arpDedupCache {
	if window <= 0 {
		return nil
	}
	now := time.Now()
	return &arpDedupCache{
		window:    window,
		now:       time.Now,
		last:      map[string]time.Time{},
		macIP:     map[string]string{},
		ipMAC:     map[string]string{},
		nextSweep: now.Add(window),
	}
}

// arpRequestAllowed keeps only ARP replies when replies-only capture is on.
// Replies carry an authoritative sender binding; requests are broadcast
// queries that dominate the storm and are frequently spoofed.
func arpRequestAllowed(repliesOnly bool, event normalized.Event) bool {
	if !repliesOnly || event.SourceEventType != "arp" {
		return true
	}
	return event.Payload != nil && event.Payload["address_binding"] == true
}

// allow reports whether the event should be written to the capture batch.
// Non-ARP events, withdrawals, and incomplete ARP subjects always pass.
func (c *arpDedupCache) allow(event normalized.Event) bool {
	if c == nil || event.SourceEventType != "arp" {
		return true
	}
	if event.Payload != nil && event.Payload["withdrawn"] == true {
		return true
	}
	mac, ip := str(event.Subject, "mac"), str(event.Subject, "ip")
	if mac == "" || ip == "" {
		return true
	}
	prefix := event.Source + "\x00" + str(event.Observer, "sensor_id") + "\x00"
	mac, ip = prefix+mac, prefix+ip
	now := c.now()
	if now.After(c.nextSweep) {
		c.sweep(now)
		c.nextSweep = now.Add(c.window)
	}
	if previousIP, ok := c.macIP[mac]; ok && previousIP != ip {
		delete(c.last, mac+"\x00"+previousIP)
		delete(c.ipMAC, previousIP)
	}
	if previousMAC, ok := c.ipMAC[ip]; ok && previousMAC != mac {
		delete(c.last, previousMAC+"\x00"+ip)
		delete(c.macIP, previousMAC)
	}
	key := mac + "\x00" + ip
	if at, ok := c.last[key]; ok && now.Sub(at) < c.window {
		return false
	}
	c.last[key] = now
	c.macIP[mac] = ip
	c.ipMAC[ip] = mac
	return true
}

func (c *arpDedupCache) sweep(now time.Time) {
	for key, at := range c.last {
		if now.Sub(at) >= c.window {
			delete(c.last, key)
		}
	}
	for mac, ip := range c.macIP {
		if _, ok := c.last[mac+"\x00"+ip]; !ok {
			delete(c.macIP, mac)
		}
	}
	for ip, mac := range c.ipMAC {
		if _, ok := c.last[mac+"\x00"+ip]; !ok {
			delete(c.ipMAC, ip)
		}
	}
}
