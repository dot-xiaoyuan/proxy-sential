package zeek

import "testing"

func TestDHCPPreservesLeaseAndFingerprint(t *testing.T) {
	p := dhcpPayload(map[string]string{"lease_time": "7200.000000", "lease_observed_at": "1789537676.8", "requested_options": "1,3,6,15", "vendor_class": "MSFT 5.0", "msg_types": "REQUEST,ACK", "client_id_hwtype": "1", "client_id_hwaddr": "02:00:00:00:00:10", "option93_present": "true"})
	for _, k := range []string{"lease_time", "lease_observed_at", "requested_options", "vendor_class"} {
		if p[k] == nil {
			t.Fatalf("missing %s", k)
		}
	}
	if p["client_id_hwtype"] != "1" || p["client_id_hwaddr"] != "02:00:00:00:00:10" || p["option93_present"] != true {
		t.Fatalf("DHCP option 61/93 presence was lost: %+v", p)
	}
}

func TestDHCPMessageRequestDoesNotCreateAddressBinding(t *testing.T) {
	fields := map[string]string{"ts": "1789537676.8", "mac": "02:00:00:00:00:10", "requested_addr": "192.168.1.12", "msg_types": "REQUEST", "vendor_class": "MSFT 5.0", "requested_options": "1,3,6,15"}
	event, err := dhcpEventFromFields([]byte(`{"msg_types":"REQUEST"}`), fields, 0, Options{LogKind: "dhcp-message", SensorID: "sensor-a"})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != "device" || event.Payload["request_only"] != true || event.Subject["ip"] != nil || event.Payload["requested_addr"] != "192.168.1.12" {
		t.Fatalf("request must remain a MAC clue without a current address: %+v", event)
	}
	fields["msg_types"], fields["assigned_addr"] = "ACK", "192.168.1.12"
	ack, err := dhcpEventFromFields([]byte(`{"msg_types":"ACK"}`), fields, 1, Options{LogKind: "dhcp-message", SensorID: "sensor-a"})
	if err != nil || ack.Type != "device" || ack.Payload["request_only"] == true || ack.Subject["ip"] != "192.168.1.12" {
		t.Fatalf("ACK should keep its explicit assigned address: %+v, %v", ack, err)
	}
	fields["msg_types"] = "OFFER"
	offer, err := dhcpEventFromFields([]byte(`{"msg_types":"OFFER"}`), fields, 2, Options{LogKind: "dhcp-message", SensorID: "sensor-a"})
	if err != nil || offer.Type == "device" || offer.Type == "discovery" {
		t.Fatalf("OFFER must not produce device evidence: %+v, %v", offer, err)
	}
}

func TestDHCPMessageWithMissingOrInvalidIdentityStaysNonProjectable(t *testing.T) {
	for _, fields := range []map[string]string{
		{"ts": "1789537676.8", "msg_types": "REQUEST", "requested_addr": "192.168.1.12", "mac": "bad-mac"},
		{"ts": "1789537676.8", "msg_types": "ACK", "assigned_addr": "192.168.1.12", "mac": "ff:ff:ff:ff:ff:ff"},
		{"ts": "1789537676.8", "msg_types": "ACK", "assigned_addr": "not-an-ip", "mac": "02:00:00:00:00:10"},
		{"ts": "1789537676.8", "msg_types": "DISCOVER"},
	} {
		event, err := dhcpEventFromFields([]byte(`{"msg_types":"incomplete"}`), fields, 0, Options{LogKind: "dhcp-message", SensorID: "sensor-a"})
		if err != nil || event.Type != "dhcp_message" || event.Payload["request_only"] == true {
			t.Fatalf("incomplete DHCP message should stay non-projectable: %+v, %v", event, err)
		}
		if event.Subject["mac"] == "bad-mac" || event.Subject["mac"] == "ff:ff:ff:ff:ff:ff" || event.Subject["ip"] == "not-an-ip" {
			t.Fatalf("invalid identity leaked into subject: %+v", event.Subject)
		}
	}
}
