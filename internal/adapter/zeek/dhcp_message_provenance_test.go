package zeek

import "testing"

func TestDHCPMessagePreservesTransactionAndClientHeader(t *testing.T) {
	f := map[string]string{"ts": "1789537676.8", "uid": "CfullUid", "xid": "4294967295", "request_uid": "Creq", "ack_uid": "Cack", "msg_types": "REQUEST", "mac": "02:00:00:00:00:10", "client_chaddr": "02:00:00:00:00:10", "client_id_hwaddr": "02:00:00:00:00:10:42:56", "capture_vlan": "997/997", "requested_options": "1,3,6", "option_order": "53,55,61"}
	e, err := dhcpEventFromFields([]byte("request"), f, 0, Options{LogKind: "dhcp-message"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"uid", "xid", "request_uid", "ack_uid", "client_chaddr"} {
		if e.Payload[k] != f[k] {
			t.Errorf("lost %s: %v", k, e.Payload[k])
		}
	}
	if e.Payload["dhcp_log_kind"] != "dhcp-message" || e.Payload["dhcp_options"] != "53,55,61" || e.Payload["client_id_hwaddr"] != f["client_id_hwaddr"] {
		t.Fatalf("lost message provenance: %+v", e.Payload)
	}
}

func TestDHCPMessageReleaseDoesNotWithdrawRequestedAddress(t *testing.T) {
	f := map[string]string{"ts": "1789537676.8", "msg_types": "RELEASE", "mac": "02:00:00:00:00:10", "client_addr": "192.168.1.12", "requested_addr": "192.168.1.99"}
	e, err := dhcpEventFromFields([]byte("release"), f, 0, Options{LogKind: "dhcp-message"})
	if err != nil || e.Subject["ip"] != "192.168.1.12" {
		t.Fatalf("release chose proposal instead of client address: %+v %v", e, err)
	}
	f["client_addr"] = ""
	e, err = dhcpEventFromFields([]byte("release"), f, 0, Options{LogKind: "dhcp-message"})
	if err != nil || e.Subject["ip"] != nil {
		t.Fatalf("release invented lease: %+v %v", e, err)
	}
}

func TestDHCPMessagePrefersHeaderWithoutTruncatingClientID(t *testing.T) {
	for _, kind := range []string{"dhcp-message", "dhcp-binding"} {
		f := map[string]string{"ts": "1789537676.8", "msg_types": "ACK", "assigned_addr": "192.168.1.12", "mac": "e0:5d:54:e9:b5:88:42:56", "client_id_hwaddr": "e0:5d:54:e9:b5:88:42:56", "client_chaddr": "e0:5d:54:e9:b5:88"}
		e, err := dhcpEventFromFields([]byte("header"), f, 0, Options{LogKind: kind})
		if err != nil || e.Subject["mac"] != f["client_chaddr"] || e.Payload["client_id_hwaddr"] != f["client_id_hwaddr"] {
			t.Fatalf("header/address or opaque ID lost: %+v %v", e, err)
		}
		delete(f, "client_chaddr")
		e, err = dhcpEventFromFields([]byte("no-header"), f, 0, Options{LogKind: kind})
		if err != nil || e.Subject["mac"] != nil {
			t.Fatalf("eight byte client identifier was truncated: %+v %v", e, err)
		}
	}
}

func TestDHCPMessageHeaderAndOpaqueClientIDLengths(t *testing.T) {
	const mac = "02:00:00:00:00:10"
	cases := []struct {
		name, htype, hlen, header, clientID, wantMAC string
	}{
		{"six_byte_header_with_short_id", "1", "6", mac, "aa:bb:cc", mac},
		{"six_byte_header_with_conflicting_long_id", "1", "6", mac, "02:ff:ff:ff:ff:ff:42:56", mac},
		{"eight_byte_header_and_id", "1", "8", mac + ":42:56", mac + ":42:56", ""},
		{"short_header_and_long_id", "1", "5", "02:00:00:00:10", mac + ":42:56:aa", ""},
		{"non_ethernet_eight_byte_header", "6", "8", mac + ":42:56", mac + ":42:56", ""},
		{"absent_header_with_opaque_six_byte_id", "", "", "", mac, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]string{
				"ts": "1789537676.8", "msg_types": "REQUEST", "capture_vlan": "998",
				"htype": tc.htype, "hlen": tc.hlen, "client_chaddr": tc.header,
				"client_id_hwaddr": tc.clientID, "requested_options": "1,3,138",
			}
			event, err := dhcpEventFromFields([]byte(tc.name), fields, 0, Options{LogKind: "dhcp-message"})
			if err != nil {
				t.Fatal(err)
			}
			if event.Payload["client_id_hwaddr"] != tc.clientID {
				t.Fatalf("lost original client identifier: %v", event.Payload["client_id_hwaddr"])
			}
			if tc.header != "" && (event.Payload["client_chaddr"] != tc.header || event.Payload["htype"] != tc.htype || event.Payload["hlen"] != tc.hlen) {
				t.Fatalf("changed source header fields: %+v", event.Payload)
			}
			got, _ := event.Subject["mac"].(string)
			if got != tc.wantMAC || event.Subject["ip"] != nil {
				t.Fatalf("unexpected request identity: %+v", event.Subject)
			}
			if tc.wantMAC == "" && event.Type != "dhcp_message" || tc.wantMAC != "" && (event.Type != "device" || event.Payload["request_only"] != true) {
				t.Fatalf("unexpected request classification: type=%s request_only=%v", event.Type, event.Payload["request_only"])
			}
		})
	}
}
