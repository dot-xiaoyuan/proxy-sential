package store

import "testing"

func TestPassiveServerStackCluesUseResponderOnly(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	const hash = "0123456789abcdef0123456789abcdef"
	event := passiveTestEvent("ssl", "192.168.0.1", "", map[string]any{"ja3s": hash, "certificate_fingerprint": hash + hash})
	event.Flow = map[string]any{"src_ip": "192.168.0.1", "dst_ip": "192.168.0.2"}
	event.Observer["interface"] = "mirror"
	event.Payload["vlan"] = "4005"
	event.Payload["tls_stack_vlan"] = "4005/19"
	items := extractPassiveBehavior(event, scope)
	if len(items) != 2 {
		t.Fatalf("want two stack references, got %+v", items)
	}
	for _, item := range items {
		if item.IP != "192.168.0.2" || item.VLAN != "4005/19" {
			t.Fatalf("wrong owner %+v", item)
		}
	}
	delete(event.Payload, "certificate_fingerprint")
	event.Payload["certificate_chain_fps"] = hash + hash + "," + hash + hash
	event.Payload["client_certificate_chain_fps"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	items = extractPassiveBehavior(event, scope)
	if len(items) != 2 || items[1].Kind != "certificate_chain_fingerprint" || items[1].Value != hash+hash || items[1].IP != "192.168.0.2" {
		t.Fatalf("wrong chain attribution: %+v", items)
	}
	event.Flow["dst_ip"] = "203.0.113.1"
	if items = extractPassiveBehavior(event, scope); len(items) != 0 {
		t.Fatalf("external responder %+v", items)
	}
}
