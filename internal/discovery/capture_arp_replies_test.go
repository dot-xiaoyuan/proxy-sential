package discovery

import "testing"

func TestARPRequestAllowedKeepsOnlyReplies(t *testing.T) {
	reply := arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.0.5")
	reply.Payload = map[string]any{"address_binding": true}
	request := arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.0.5")
	request.Payload = map[string]any{"address_binding": false}

	if !arpRequestAllowed(true, reply) {
		t.Fatal("replies must pass")
	}
	if arpRequestAllowed(true, request) {
		t.Fatal("requests must be dropped when replies-only is enabled")
	}
	if !arpRequestAllowed(false, request) {
		t.Fatal("requests must pass when replies-only is disabled")
	}
	other := arpDedupEvent("aa:bb:cc:dd:ee:ff", "10.202.0.5")
	other.SourceEventType = "dns_sd"
	if !arpRequestAllowed(true, other) {
		t.Fatal("non-ARP evidence must pass")
	}
}
