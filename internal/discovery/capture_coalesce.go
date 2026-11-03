package discovery

import (
	"reflect"
	"time"

	"proxy-sentinel/internal/normalized"
)

// Capture groups only short, identical, positive-TTL announcements. The first
// and last producer observations remain in the one durable source event.
const passiveCaptureCoalesceWindow = time.Second

type captureCoalescer struct {
	events    []normalized.Event
	positions map[string]int
	lastKey   string
	arpByMAC  map[string]*captureARPPosition
	arpByIP   map[string]*captureARPPosition
}

type captureARPPosition struct {
	key, mac, ip string
	at           int
}

func newCaptureCoalescer() *captureCoalescer {
	return &captureCoalescer{positions: map[string]int{}, arpByMAC: map[string]*captureARPPosition{}, arpByIP: map[string]*captureARPPosition{}}
}

func captureCoalesceKey(event normalized.Event) (string, bool) {
	if len(event.RawRef) != 0 || event.Payload == nil || event.Payload["withdrawn"] == true {
		return "", false
	}
	ttl := number(event.Payload, "ttl")
	if ttl <= 0 || ttl > discoveryMaxTTLSeconds {
		return "", false
	}
	payload := make(map[string]any, len(event.Payload))
	for key, value := range event.Payload {
		if key != "ttl" {
			payload[key] = value
		}
	}
	return contentHash([]any{event.Type, event.Source, event.SourceEventType, event.Observer, event.Subject, payload, event.Confidence}), true
}

func (c *captureCoalescer) add(event normalized.Event) bool {
	key, eligible := captureCoalesceKey(event)
	if event.SourceEventType == "arp" {
		clear(c.positions)
		c.lastKey = ""
		return c.addARP(event, key, eligible)
	}
	if eligible && len(c.events) > 0 && captureSameSubject(c.events[len(c.events)-1], event) &&
		captureNonIncreasing(c.events[len(c.events)-1], event) {
		// A late or tied transition is its own evidence, even if its payload
		// differs from the previous event. Do not seed a later repeat with it.
		clear(c.positions)
		c.lastKey = ""
		c.events = append(c.events, event)
		return false
	}
	// Other protocols still combine only adjacent identical observations.
	if !eligible || key != c.lastKey {
		clear(c.positions)
	}
	if eligible {
		c.lastKey = key
	} else {
		c.lastKey = ""
	}
	if eligible {
		if at, found := c.positions[key]; found {
			if c.combine(at, event) {
				return true
			}
		}
		c.positions[key] = len(c.events)
	}
	c.events = append(c.events, event)
	return false
}

// An ARP address or MAC change invalidates the previous candidate even when
// another device was observed between them. The maps live for one capture batch.
func (c *captureCoalescer) addARP(event normalized.Event, key string, eligible bool) bool {
	mac, ip := str(event.Subject, "mac"), str(event.Subject, "ip")
	if mac == "" || ip == "" {
		clear(c.arpByMAC)
		clear(c.arpByIP)
		c.events = append(c.events, event)
		return false
	}
	prefix := event.Source + "\x00" + str(event.Observer, "sensor_id") + "\x00"
	mac, ip = prefix+mac, prefix+ip
	if eligible {
		byMAC, byIP := c.arpByMAC[mac], c.arpByIP[ip]
		if (byMAC != nil && captureNonIncreasing(c.events[byMAC.at], event)) ||
			(byIP != nil && captureNonIncreasing(c.events[byIP.at], event)) {
			// Address or content changes can be late too. Keep this event
			// independent and break both related merge candidates.
			if byMAC != nil {
				c.forgetARP(byMAC)
			}
			if byIP != nil {
				c.forgetARP(byIP)
			}
			c.events = append(c.events, event)
			return false
		}
	}
	if previous := c.arpByMAC[mac]; previous != nil && previous.key != key {
		c.forgetARP(previous)
	}
	if previous := c.arpByIP[ip]; previous != nil && previous.key != key {
		c.forgetARP(previous)
	}
	if eligible {
		if previous := c.arpByMAC[mac]; previous != nil && previous == c.arpByIP[ip] && previous.key == key {
			if c.combine(previous.at, event) {
				return true
			}
		}
	}
	if previous := c.arpByMAC[mac]; previous != nil {
		c.forgetARP(previous)
	}
	if previous := c.arpByIP[ip]; previous != nil {
		c.forgetARP(previous)
	}
	if eligible {
		position := &captureARPPosition{key: key, mac: mac, ip: ip, at: len(c.events)}
		c.arpByMAC[mac], c.arpByIP[ip] = position, position
	}
	c.events = append(c.events, event)
	return false
}

func captureNonIncreasing(previous, current normalized.Event) bool {
	previousAt, previousErr := time.Parse(time.RFC3339Nano, previous.Timestamp)
	currentAt, currentErr := time.Parse(time.RFC3339Nano, current.Timestamp)
	return previousErr == nil && currentErr == nil && !currentAt.After(previousAt)
}

func captureSameSubject(previous, current normalized.Event) bool {
	return previous.Source == current.Source && previous.SourceEventType == current.SourceEventType &&
		reflect.DeepEqual(previous.Observer, current.Observer) && reflect.DeepEqual(previous.Subject, current.Subject)
}

func (c *captureCoalescer) forgetARP(position *captureARPPosition) {
	if c.arpByMAC[position.mac] == position {
		delete(c.arpByMAC, position.mac)
	}
	if c.arpByIP[position.ip] == position {
		delete(c.arpByIP, position.ip)
	}
}

func (c *captureCoalescer) combine(at int, event normalized.Event) bool {
	previous := c.events[at]
	first := previous.Timestamp
	firstID := previous.EventID
	count := 1
	if previous.RawRef != nil {
		if value, ok := previous.RawRef["coalesced_first_observed_at"].(string); ok {
			first = value
		}
		if value, ok := previous.RawRef["coalesced_first_producer_event_id"].(string); ok {
			firstID = value
		}
		if value, ok := previous.RawRef["coalesced_count"].(int); ok {
			count = value
		}
	}
	firstAt, firstErr := time.Parse(time.RFC3339Nano, first)
	previousAt, previousErr := time.Parse(time.RFC3339Nano, previous.Timestamp)
	currentAt, currentErr := time.Parse(time.RFC3339Nano, event.Timestamp)
	previousTTL := number(previous.Payload, "ttl")
	// Equal timestamps use the event key to decide which TTL wins.
	if firstErr != nil || previousErr != nil || currentErr != nil || !currentAt.After(previousAt) ||
		previousTTL <= 0 || previousTTL > discoveryMaxTTLSeconds || !currentAt.Before(previousAt.Add(time.Duration(previousTTL)*time.Second)) ||
		currentAt.Sub(firstAt) > passiveCaptureCoalesceWindow {
		return false
	}
	event.RawRef = cloneStreamFields(event.RawRef)
	event.RawRef["coalesced_count"] = count + 1
	event.RawRef["coalesced_first_observed_at"] = first
	event.RawRef["coalesced_first_producer_event_id"] = firstID
	c.events[at] = event
	return true
}

func (c *captureCoalescer) len() int { return len(c.events) }

func (c *captureCoalescer) drain() []normalized.Event {
	events := c.events
	c.events = nil
	c.positions = map[string]int{}
	c.lastKey = ""
	c.arpByMAC = map[string]*captureARPPosition{}
	c.arpByIP = map[string]*captureARPPosition{}
	return events
}
