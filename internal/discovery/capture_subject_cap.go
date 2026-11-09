package discovery

import (
	"time"

	"proxy-sentinel/internal/normalized"
)

// captureSubjectCap bounds how many capture events a single subject address
// can contribute per protocol inside a window. Campus ARP and mDNS traffic is
// dominated by short-lived or spoofed MACs, so MAC-level deduplication cannot
// bound the durable stream. One event per address per protocol per window keeps
// coverage of the address space while making the produced volume independent of
// that churn. Withdrawals always pass.
type captureSubjectCap struct {
	window    time.Duration
	now       func() time.Time
	last      map[string]time.Time
	nextSweep time.Time
}

func newCaptureSubjectCap(window time.Duration) *captureSubjectCap {
	if window <= 0 {
		return nil
	}
	now := time.Now()
	return &captureSubjectCap{window: window, now: time.Now, last: map[string]time.Time{}, nextSweep: now.Add(window)}
}

func (c *captureSubjectCap) allow(event normalized.Event) bool {
	if c == nil {
		return true
	}
	if event.Payload != nil && event.Payload["withdrawn"] == true {
		return true
	}
	ip := str(event.Subject, "ip")
	if ip == "" {
		return true
	}
	key := event.Source + "\x00" + event.SourceEventType + "\x00" + ip
	now := c.now()
	if now.After(c.nextSweep) {
		c.sweep(now)
		c.nextSweep = now.Add(c.window)
	}
	if at, ok := c.last[key]; ok && now.Sub(at) < c.window {
		return false
	}
	c.last[key] = now
	return true
}

func (c *captureSubjectCap) sweep(now time.Time) {
	for key, at := range c.last {
		if now.Sub(at) >= c.window {
			delete(c.last, key)
		}
	}
}
