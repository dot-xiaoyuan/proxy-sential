package store

import "testing"

func TestTLSCertificateDoesNotInheritClientMAC(t *testing.T) {
	scope, err := parsePassiveDiscoveryScope("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	event := passiveTestEvent("ssl", "192.168.0.2", "00:11:22:33:44:55", map[string]any{"certificate_subject": "CN=printer", "vlan": "2701/26"})
	event.Flow = map[string]any{"src_ip": "192.168.0.2", "dst_ip": "192.168.0.10"}
	o, reason := passiveObservation(event, scope)
	if reason != "" || o.IP != "192.168.0.10" || o.MAC != "" || o.VLAN != "2701/26" {
		t.Fatalf("TLS server acquired client identity: %+v %s", o, reason)
	}
	event.Flow["dst_ip"] = "8.8.8.8"
	if _, reason = passiveObservation(event, scope); reason != "tls_device_out_of_scope" {
		t.Fatalf("external certificate admitted: %s", reason)
	}
}

func TestSSDPByeWithdrawsObservation(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	event := passiveTestEvent("ssdp", "192.168.0.10", "", map[string]any{"is_announcement": true, "withdrawn": true, "nt": "upnp:rootdevice"})
	o, reason := passiveObservation(event, scope)
	if reason != "" || !o.Withdrawn || !o.ValidUntil.Equal(o.ObservedAt) {
		t.Fatalf("bye remains active: %+v %s", o, reason)
	}
}
