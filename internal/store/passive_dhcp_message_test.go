package store

import (
	"proxy-sentinel/internal/discovery"
	"testing"
	"time"
)

func TestDHCPClientFeaturesNeverBecomeAddressLease(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	for _, action := range []string{"REQUEST", "DISCOVER", "INFORM"} {
		e := passiveTestEvent("dhcp", "", "02:00:00:00:00:10", map[string]any{"client_chaddr": "02:00:00:00:00:10", "dhcp_log_kind": "dhcp-message", "msg_types": action, "request_only": true, "requested_addr": "192.168.0.99", "vendor_class": "H3C. H3C WA5320", "requested_options": "1,3,6", "dhcp_capture_vlan": "997/997"})
		o, reason := passiveObservation(e, scope)
		if reason != "" || o.Origin != "dhcp_client" || o.IP != "" || o.VLAN != "997/997" || o.Confidence == "confirmed" || o.ValidUntil.Sub(o.ObservedAt) != 10*time.Minute {
			t.Fatalf("%s client clue lost or became lease: %+v %s", action, o, reason)
		}
		fact, err := discovery.HardwareFactFromObservation(o)
		if err != nil || fact == nil || len(fact.Signals) < 2 {
			t.Fatalf("features did not reach scoped hardware fact: %+v %v", fact, err)
		}
	}
}

func TestDHCPClientFeaturesRequireValidatedMessage(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	for _, p := range []map[string]any{
		{"msg_types": "REQUEST", "vendor_class": "H3C. H3C WA5320"},
		{"dhcp_log_kind": "dhcp-message", "msg_types": "OFFER", "vendor_class": "H3C. H3C WA5320"},
		{"dhcp_log_kind": "dhcp-message", "msg_types": "REQUEST", "vendor_class": "H3C. H3C WA5320", "discovery_scope_conflict": true},
	} {
		e := passiveTestEvent("dhcp", "", "02:00:00:00:00:10", p)
		if o, reason := passiveObservation(e, scope); reason == "" {
			t.Fatalf("invalid client feature accepted: %+v", o)
		}
	}
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "false")
	e := passiveTestEvent("dhcp", "", "02:00:00:00:00:10", map[string]any{"dhcp_log_kind": "dhcp-message", "msg_types": "REQUEST", "request_only": true, "vendor_class": "H3C. H3C WA5320"})
	if _, reason := passiveObservation(e, scope); reason == "" {
		t.Fatal("184 legacy path changed")
	}
}

func TestDHCPClientFeatureDedupAndHeaderOwnership(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	e := passiveTestEvent("dhcp", "", "02:00:00:00:00:10", map[string]any{"dhcp_log_kind": "dhcp-message", "msg_types": "REQUEST", "request_only": true, "vendor_class": "MSFT 5.0", "requested_options": "1,3,6", "uid": "C1"})
	if _, reason := passiveObservation(e, scope); reason != "dhcp_client_mac_source_unverified" {
		t.Fatalf("unverified MAC source accepted: %s", reason)
	}
	e.Payload["client_id_hwtype"] = "1"
	e.Payload["client_id_hwaddr"] = "02:00:00:00:00:10"
	a, reason := passiveObservation(e, scope)
	if reason != "" {
		t.Fatal(reason)
	}
	if f, err := discovery.HardwareFactFromObservation(a); err != nil || f == nil {
		t.Fatalf("typed Ethernet client identifier lost: %+v %v", f, err)
	}
	e.EventID = "repeat"
	e.Timestamp = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	e.Payload["uid"] = "C2"
	b, _ := passiveObservation(e, scope)
	if a.ID != b.ID || a.EventID == b.EventID {
		t.Fatal("repeat must compact while retaining latest original reference")
	}
	e.Payload["vendor_class"] = "different"
	c, _ := passiveObservation(e, scope)
	if c.ID == b.ID {
		t.Fatal("different fields were folded")
	}
	e.Payload["vendor_class"] = "MSFT 5.0"
	e.Payload["dhcp_capture_vlan"] = "2"
	d, _ := passiveObservation(e, scope)
	if d.ID == b.ID {
		t.Fatal("different scope was folded")
	}
}
