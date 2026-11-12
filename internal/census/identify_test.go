package census

import (
	"net/netip"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func testEvent(kind, ip, mac string) normalized.Event {
	return normalized.Event{
		EventID: "event-1", Timestamp: "2026-11-10T09:00:00Z", Source: "zeek", SourceEventType: kind,
		Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
		Subject:  map[string]any{"ip": ip, "mac": mac, "campus_id": "campus"},
		Payload:  map[string]any{"access_domain": "mirror", "vlan": "20"},
		Flow:     map[string]any{},
	}
}

func testPrefixes(t *testing.T) []netip.Prefix {
	t.Helper()
	return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("222.204.0.0/16")}
}

func TestIdentifyCountsBothLocalFlowSidesWithoutInventingMAC(t *testing.T) {
	event := testEvent("flow", "10.1.1.2", "00:11:22:33:44:55")
	event.Flow = map[string]any{"src_ip": "10.1.1.2", "dst_ip": "222.204.3.4"}
	ids, bindings := Identify(event, testPrefixes(t))
	if len(ids) != 2 || ids[0].Kind != "ip" || ids[0].Value != "10.1.1.2" || ids[1].Value != "222.204.3.4" || len(bindings) != 0 {
		t.Fatalf("flow identifiers=%+v bindings=%+v", ids, bindings)
	}
}

func TestIdentifyKeepsScopedARPBindingAndRandomMAC(t *testing.T) {
	event := testEvent("arp", "10.1.1.2", "02:11:22:33:44:55")
	ids, bindings := Identify(event, testPrefixes(t))
	if len(ids) != 2 || ids[1].Kind != "mac" || !ids[1].RandomMAC || len(bindings) != 1 || bindings[0].IP != "10.1.1.2" || bindings[0].MAC != "02:11:22:33:44:55" {
		t.Fatalf("arp identifiers=%+v bindings=%+v", ids, bindings)
	}
	other := event
	other.Subject = map[string]any{"ip": "10.1.1.2", "mac": "02:11:22:33:44:55", "campus_id": "campus"}
	other.Payload = map[string]any{"access_domain": "mirror", "vlan": "21"}
	otherIDs, _ := Identify(other, testPrefixes(t))
	if ids[1].ScopeKey == otherIDs[1].ScopeKey {
		t.Fatal("same MAC from different VLANs was merged")
	}
}

func TestIdentifyDHCPRequestDoesNotCreateBindingAndWithdrawalExpiresIt(t *testing.T) {
	event := testEvent("dhcp", "10.1.1.3", "00:11:22:33:44:55")
	event.Payload["msg_types"] = "REQUEST"
	ids, bindings := Identify(event, testPrefixes(t))
	if len(ids) != 1 || ids[0].Kind != "mac" || len(bindings) != 0 {
		t.Fatalf("request identifiers=%+v bindings=%+v", ids, bindings)
	}
	event.Payload["msg_types"] = "ACK"
	event.Payload["lease_time"] = "600"
	_, bindings = Identify(event, testPrefixes(t))
	if len(bindings) != 1 || bindings[0].ValidUntil.Sub(time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)) != 600*time.Second {
		t.Fatalf("ack binding=%+v", bindings)
	}
	event.Payload["withdrawn"] = true
	_, bindings = Identify(event, testPrefixes(t))
	if len(bindings) != 1 || !bindings[0].Withdrawn || !bindings[0].ValidUntil.Equal(bindings[0].ObservedAt) {
		t.Fatalf("withdrawal binding=%+v", bindings)
	}
	event.Payload = map[string]any{"message_type": "release"}
	_, bindings = Identify(event, testPrefixes(t))
	if len(bindings) != 1 || !bindings[0].Withdrawn {
		t.Fatalf("release action did not withdraw binding: %+v", bindings)
	}
	event.Payload = map[string]any{"message_type": "ack", "lease_time": float64(300)}
	_, bindings = Identify(event, testPrefixes(t))
	if len(bindings) != 1 || bindings[0].Withdrawn || bindings[0].ValidUntil.Sub(bindings[0].ObservedAt) != 300*time.Second {
		t.Fatalf("message_type ACK binding=%+v", bindings)
	}
}

func TestIdentifyRejectsRemoteAndInvalidSubjectMAC(t *testing.T) {
	event := testEvent("arp", "8.8.8.8", "ff:ff:ff:ff:ff:ff")
	ids, bindings := Identify(event, testPrefixes(t))
	if len(ids) != 0 || len(bindings) != 0 {
		t.Fatalf("remote or broadcast admitted: %+v %+v", ids, bindings)
	}
	event = testEvent("mdns", "10.1.1.4", "00:11:22:33:44:55")
	ids, _ = Identify(event, testPrefixes(t))
	if len(ids) != 1 {
		t.Fatalf("unverified service MAC admitted: %+v", ids)
	}
	event.Payload["l2_source_mac_direct"] = true
	event.Payload["responder_l2_mac"] = "00:11:22:33:44:55"
	event.Flow["src_ip"] = "10.1.1.4"
	ids, _ = Identify(event, testPrefixes(t))
	if len(ids) != 2 || ids[1].Kind != "mac" {
		t.Fatalf("direct responder ownership lost: %+v", ids)
	}
	event.Flow["src_ip"] = "10.1.1.9"
	ids, _ = Identify(event, testPrefixes(t))
	if len(ids) != 2 || ids[1].Kind != "ip" {
		t.Fatalf("service target inherited responder MAC: %+v", ids)
	}
}

func TestIdentifyRejectsConfiguredSubnetBroadcast(t *testing.T) {
	event := testEvent("flow", "10.1.255.255", "")
	event.Flow = map[string]any{"src_ip": "10.1.0.0", "dst_ip": "10.1.2.3"}
	ids, _ := Identify(event, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")})
	if len(ids) != 1 || ids[0].Value != "10.1.2.3" {
		t.Fatalf("non-unicast subnet address counted: %+v", ids)
	}
}

func TestIdentifyDualStackAndGatewayFrameMAC(t *testing.T) {
	event := testEvent("flow", "", "00:11:22:33:44:55")
	event.Flow = map[string]any{"src_ip": "2001:db8:20::1", "dst_ip": "10.20.0.2"}
	event.Payload["ethernet_source_mac"] = "00:11:22:33:44:55" // often the mirror's gateway
	event.Payload["ethernet_destination_mac"] = "00:11:22:33:44:66"
	prefixes := append(testPrefixes(t), netip.MustParsePrefix("2001:db8:20::/64"))
	ids, bindings := Identify(event, prefixes)
	if len(ids) != 2 || ids[0].IPFamily != 6 || ids[1].IPFamily != 4 || len(bindings) != 0 {
		t.Fatalf("dual-stack flow admitted a frame MAC or lost IPs: %+v %+v", ids, bindings)
	}
}

func TestIdentifyVerifiedPacketSidecarResponderMAC(t *testing.T) {
	event := testEvent("ssdp", "10.1.1.4", "00:11:22:33:44:55")
	event.Source = "packet-sidecar"
	event.Flow["src_ip"] = "10.1.1.4"
	ids, _ := Identify(event, testPrefixes(t))
	if len(ids) != 2 || ids[1].Kind != "mac" {
		t.Fatalf("frame-source MAC lost: %+v", ids)
	}
	event.Flow["src_ip"] = "10.1.1.9"
	ids, _ = Identify(event, testPrefixes(t))
	if len(ids) != 2 || ids[1].Kind != "ip" {
		t.Fatalf("advertised target inherited frame MAC: %+v", ids)
	}
}
