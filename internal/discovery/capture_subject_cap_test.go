package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func capEvent(protocol, ip string) normalized.Event {
	return normalized.Event{
		Source:          "discovery-worker",
		SourceEventType: protocol,
		Observer:        map[string]any{"sensor_id": "sensor-a"},
		Subject:         map[string]any{"ip": ip, "mac": "aa:bb:cc:dd:ee:ff"},
	}
}

func TestSubjectCapBoundsOneEventPerAddressAndProtocol(t *testing.T) {
	c := newCaptureSubjectCap(600 * time.Second)
	now := time.Unix(4000, 0)
	c.now = func() time.Time { return now }

	if !c.allow(capEvent("arp", "10.202.0.5")) {
		t.Fatal("first arp event must pass")
	}
	if c.allow(capEvent("arp", "10.202.0.5")) {
		t.Fatal("second arp event for the same address must be capped")
	}
	if !c.allow(capEvent("dns_sd", "10.202.0.5")) {
		t.Fatal("a different protocol must keep its own budget")
	}
	now = now.Add(601 * time.Second)
	if !c.allow(capEvent("arp", "10.202.0.5")) {
		t.Fatal("the next window must pass")
	}
}

func TestSubjectCapPassesWithdrawalsAndUnknownAddresses(t *testing.T) {
	c := newCaptureSubjectCap(time.Minute)
	withdrawn := capEvent("dns_sd", "10.202.0.6")
	withdrawn.Payload = map[string]any{"withdrawn": true}
	if !c.allow(withdrawn) {
		t.Fatal("withdrawals must pass")
	}
	noIP := normalized.Event{SourceEventType: "arp", Subject: map[string]any{"mac": "aa"}}
	if !c.allow(noIP) {
		t.Fatal("events without an address must pass")
	}
}

func TestSubjectCapDisabledWhenZero(t *testing.T) {
	if newCaptureSubjectCap(0) != nil {
		t.Fatal("zero window must disable the cap")
	}
	var disabled *captureSubjectCap
	if !disabled.allow(capEvent("arp", "10.202.0.5")) {
		t.Fatal("nil cap must pass events")
	}
}

func TestSubjectCapSweepDropsExpiredEntries(t *testing.T) {
	c := newCaptureSubjectCap(time.Minute)
	now := time.Unix(5000, 0)
	c.now = func() time.Time { return now }
	c.allow(capEvent("arp", "10.202.0.5"))
	now = now.Add(2 * time.Minute)
	c.sweep(now)
	if len(c.last) != 0 {
		t.Fatalf("sweep left %d entries", len(c.last))
	}
}
