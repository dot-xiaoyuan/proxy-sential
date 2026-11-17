package store

import (
	"context"
	"testing"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func directMACTXTEvent(mac string, direct bool) normalized.Event {
	payload := map[string]any{"l2_source_mac_direct": true, "responder_l2_mac": mac}
	if !direct {
		payload = map[string]any{}
	}
	return normalized.Event{
		Source:  "zeek",
		Flow:    map[string]any{"dst_ip": "224.0.0.251"},
		Subject: map[string]any{"mac": mac},
		Payload: payload,
	}
}

func TestPassiveObservationLinkAllowsDirectMACWithoutIP(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"
	o := discovery.Observation{Origin: "dns_sd", MAC: mac, Evidence: directMACTXTEvent(mac, true)}
	link, err := (&DBStore{}).passiveObservationLink(context.Background(), nil, o)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if link == nil || link.EndpointID != "mac:"+mac {
		t.Fatalf("direct MAC without IP must link by MAC: %+v", link)
	}
}

func TestPassiveObservationLinkRejectsRandomMACWithoutIP(t *testing.T) {
	mac := "02:11:22:33:44:55"
	o := discovery.Observation{Origin: "dns_sd", MAC: mac, Evidence: directMACTXTEvent(mac, false)}
	link, err := (&DBStore{}).passiveObservationLink(context.Background(), nil, o)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if link != nil {
		t.Fatalf("random MAC without IP or direct identity must not link: %+v", link)
	}
}
