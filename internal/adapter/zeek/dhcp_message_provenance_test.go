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
