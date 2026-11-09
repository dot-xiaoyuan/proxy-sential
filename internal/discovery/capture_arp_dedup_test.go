package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func arpDedupEvent(mac, ip string) normalized.Event {
	return normalized.Event{
		Source:          "discovery-worker",
		SourceEventType: "arp",
		Observer:        map[string]any{"sensor_id": "sensor-a"},
		Subject:         map[string]any{"mac": mac, "ip": ip},
	}
}

func TestARPDedupSuppressesRepeatsAndRefreshesAfterWindow(t *testing.T) {
	cache := newARPDedupCache(time.Minute)
	now := time.Unix(1000, 0)
	cache.now = func() time.Time { return now }

	event := arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.10")
	if !cache.allow(event) {
		t.Fatal("first observation must pass")
	}
	if cache.allow(event) {
		t.Fatal("repeat inside the window must be dropped")
	}
	now = now.Add(61 * time.Second)
	if !cache.allow(event) {
		t.Fatal("refresh after the window must pass")
	}
}

func TestARPDedupPassesAddressChanges(t *testing.T) {
	cache := newARPDedupCache(time.Minute)
	now := time.Unix(2000, 0)
	cache.now = func() time.Time { return now }

	if !cache.allow(arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.10")) {
		t.Fatal("first binding must pass")
	}
	if !cache.allow(arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.11")) {
		t.Fatal("changed address must pass")
	}
	if cache.allow(arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.11")) {
		t.Fatal("repeat of the changed binding must be dropped")
	}
	if !cache.allow(arpDedupEvent("11:22:33:44:55:66", "10.202.1.10")) {
		t.Fatal("address taken by a new MAC must pass")
	}
}

func TestARPDedupAlwaysPassesOtherEvidence(t *testing.T) {
	cache := newARPDedupCache(time.Minute)
	withdrawn := arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.10")
	withdrawn.Payload = map[string]any{"withdrawn": true}
	if !cache.allow(withdrawn) {
		t.Fatal("withdrawals must pass")
	}
	other := arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.10")
	other.SourceEventType = "dns_sd"
	if !cache.allow(other) {
		t.Fatal("non-ARP evidence must pass")
	}
	incomplete := normalized.Event{SourceEventType: "arp", Subject: map[string]any{"mac": "aa:bb"}}
	if !cache.allow(incomplete) {
		t.Fatal("incomplete ARP subject must pass")
	}
}

func TestARPDedupDisabledWhenWindowIsZero(t *testing.T) {
	if newARPDedupCache(0) != nil {
		t.Fatal("zero window must disable dedup")
	}
	var disabled *arpDedupCache
	if !disabled.allow(arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.10")) {
		t.Fatal("nil cache must pass events")
	}
}

func TestARPDedupSweepDropsExpiredEntries(t *testing.T) {
	cache := newARPDedupCache(time.Minute)
	now := time.Unix(3000, 0)
	cache.now = func() time.Time { return now }
	cache.allow(arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.1.10"))
	now = now.Add(2 * time.Minute)
	cache.sweep(now)
	if len(cache.last) != 0 || len(cache.macIP) != 0 || len(cache.ipMAC) != 0 {
		t.Fatalf("sweep left stale entries: %d/%d/%d", len(cache.last), len(cache.macIP), len(cache.ipMAC))
	}
}
