package discovery

import (
	"encoding/binary"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestProtocolMetadataAdmissionAndNegativeCases(t *testing.T) {
	p, e := ParseMQTTDiscovery("homeassistant/sensor/test/config", []byte(`{"device":{"manufacturer":"Example","model":"S1"}}`), true)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	o := Observation{Origin: "mqtt", ObservedAt: now, ValidUntil: now.Add(time.Hour), Evidence: normalized.Event{Payload: p}}
	if c := ClassifyIoT([]Observation{o}, now); c.DeviceType != "" {
		t.Fatalf("publisher incorrectly classified %+v", c)
	}
	o.Evidence.Payload["self_binding_verified"] = true
	if c := ClassifyIoT([]Observation{o}, now); c.DeviceType != "sensor" {
		t.Fatalf("bound declaration missing %+v", c)
	}
	for _, topic := range []string{"telemetry/sensor", "homeassistant/sensor/test/state"} {
		if _, e = ParseMQTTDiscovery(topic, []byte(`{"device":{"model":"S1"}}`), true); e == nil {
			t.Fatal("telemetry accepted")
		}
	}
	if _, e = ParseMQTTDiscovery("homeassistant/sensor/test/config", []byte(`{}`), false); e == nil {
		t.Fatal("broker forwarding attributed to broker")
	}
	// BACnet/IP original broadcast NPDU, unconfirmed I-Am, device object 123.
	b := []byte{0x81, 0x0b, 0, 13, 1, 0, 0x10, 0, 0xc4, 2, 0, 0, 123}
	p, e = ParseBACnetAnnouncement(b)
	if e != nil || p["device_identifier"] != "123" {
		t.Fatalf("BACnet %v %v", p, e)
	}
	b[7] = 8
	if _, e = ParseBACnetAnnouncement(b); e == nil {
		t.Fatal("Who-Is attributed to sender")
	}
	// CoAP 2.05 Content, application/link-format=40, explicit OCF device type.
	coap := append([]byte{0x60, 69, 0, 1, 0xc1, 40, 0xff}, []byte(`</oic/d>;rt="oic.d.sensor"`)...)
	p, e = ParseCoAPResponse(coap)
	if e != nil || p["device_resource_type"] != "oic.d.sensor" {
		t.Fatalf("CoAP %v %v", p, e)
	}
	coap[1] = 1
	if _, e = ParseCoAPResponse(coap); e == nil {
		t.Fatal("CoAP request admitted")
	}
}
func TestDHCPv6ClientIdentityNotServerAddress(t *testing.T) {
	b := []byte{7, 1, 2, 3, 0, 1, 0, 4, 0, 3, 0, 1, 0, 3, 0, 40}
	ia := make([]byte, 40)
	binary.BigEndian.PutUint32(ia[:4], 7)
	binary.BigEndian.PutUint16(ia[12:14], 5)
	binary.BigEndian.PutUint16(ia[14:16], 24)
	ia[16] = 0xfd
	ia[31] = 1
	binary.BigEndian.PutUint32(ia[36:40], 3600)
	b = append(b, ia...)
	bindings, withdrawn, e := ParseDHCPv6(b)
	if e != nil || withdrawn || len(bindings) != 1 || bindings[0].IP != "fd00::1" || bindings[0].Valid != 3600 {
		t.Fatalf("DHCPv6 %+v %v", bindings, e)
	}
	b[0] = 1
	if _, _, e = ParseDHCPv6(b); e == nil {
		t.Fatal("solicit accepted")
	}
	b[0] = 8
	bindings, withdrawn, e = ParseDHCPv6(b)
	if e != nil || !withdrawn || bindings[0].Valid != 0 {
		t.Fatal("release not applied")
	}
}

func TestIPPAttributesResponseBounds(t *testing.T) {
	raw := []byte{1, 1, 0, 0, 0, 0, 0, 1, 4, 0x41, 0, 22}
	raw = append(raw, []byte("printer-make-and-model")...)
	raw = append(raw, 0, 7)
	raw = append(raw, []byte("HP M404")...)
	raw = append(raw, 3)
	p, e := ParseIPPAttributes(raw)
	if e != nil || p["printer_make_and_model"] != "HP M404" {
		t.Fatalf("%v %v", p, e)
	}
	if _, e = ParseIPPAttributes(raw[:len(raw)-2]); e == nil {
		t.Fatal("truncated response admitted")
	}
}

func TestZeekDHCPAdapterAcceptsBindingOnly(t *testing.T) {
	for _, tc := range []struct {
		action              string
		accepted, withdrawn bool
	}{{"DISCOVER,REQUEST", false, false}, {"REQUEST,ACK", true, false}, {"RELEASE", true, true}} {
		e := normalized.Event{Source: "zeek", SourceEventType: "dhcp", Payload: map[string]any{"msg_types": tc.action, "lease_time": "600"}}
		a, err := AdaptDiscoveryEvent(e)
		if (err == nil) != tc.accepted {
			t.Fatalf("%s: %v", tc.action, err)
		}
		if err == nil && (a.Payload["withdrawn"] == true) != tc.withdrawn {
			t.Fatalf("%s: %+v", tc.action, a)
		}
	}
}
