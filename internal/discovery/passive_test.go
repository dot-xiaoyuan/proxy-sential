package discovery

import (
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"testing"
	"time"
)

func TestMDNSDoesNotNameQuerySender(t *testing.T) {
	name := dnsmessage.MustNewName("Printer._ipp._tcp.local.")
	host := dnsmessage.MustNewName("printer.local.")
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.SRVResource{Port: 631, Target: host}}}}
	packet := func() []byte {
		b, e := msg.Pack()
		if e != nil {
			t.Fatal(e)
		}
		f := make([]byte, 42+len(b))
		f[12] = 8
		f[14] = 0x45
		binary.BigEndian.PutUint16(f[16:18], uint16(28+len(b)))
		f[23] = 17
		copy(f[26:30], []byte{192, 0, 2, 100})
		binary.BigEndian.PutUint16(f[34:36], 5353)
		binary.BigEndian.PutUint16(f[36:38], 5353)
		binary.BigEndian.PutUint16(f[38:40], uint16(8+len(b)))
		copy(f[42:], b)
		return f
	}
	s := Source{ID: "passive", Node: "n", Site: "s", Domain: "d"}
	events := DecodeFrame(packet(), s, time.Now())
	if len(events) != 1 || events[0].Subject["ip"] != "" {
		t.Fatal("unresolved target assigned to sender")
	}
	msg.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: host, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
	events = DecodeFrame(packet(), s, time.Now())
	if len(events) != 1 || events[0].Subject["ip"] != "192.0.2.1" {
		t.Fatal("target not resolved")
	}
	msg.Header.Response = false
	if len(DecodeFrame(packet(), s, time.Now())) != 0 {
		t.Fatal("query attributed")
	}
}

func TestLLDPTruncatedDoesNotAttribute(t *testing.T) {
	f := make([]byte, 17)
	f[12] = 0x88
	f[13] = 0xcc
	f[14] = 2
	f[15] = 10
	if len(DecodeFrame(f, Source{}, time.Now())) != 0 {
		t.Fatal("truncated LLDP accepted")
	}
}

func TestARPReplyCreatesAddressClaimOnly(t *testing.T) {
	frame := make([]byte, 14+28)
	copy(frame[6:12], []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 2)
	copy(arp[8:14], frame[6:12])
	copy(arp[14:18], []byte{10, 152, 42, 13})
	source := Source{ID: "pilot", Node: "ncu", Site: "ncu", Domain: "bond0"}
	events := DecodeFrame(frame, source, time.Now())
	if len(events) != 1 {
		t.Fatalf("ARP reply was not decoded: %+v", events)
	}
	allow, err := ParseCaptureCIDRs("10.152.40.0/22")
	if err != nil {
		t.Fatal(err)
	}
	if len(filterCaptureEvents(events, allow)) != 1 {
		t.Fatal("in-scope ARP reply was filtered")
	}
	observation, err := FromEvent(events[0])
	if err != nil || observation.IP != "10.152.42.13" ||
		observation.MAC != "00:11:22:33:44:55" || observation.DeviceType != "" {
		t.Fatalf("unexpected ARP observation: %+v, %v", observation, err)
	}
	arp[7] = 1
	if len(DecodeFrame(frame, source, time.Now())) != 0 {
		t.Fatal("ARP request attributed as device evidence")
	}
	arp[7] = 2
	arp[8] = 0x66
	if len(DecodeFrame(frame, source, time.Now())) != 0 {
		t.Fatal("mismatched ARP sender MAC attributed as device evidence")
	}
}

func TestSSDPNotifyWithdrawalUsesSameService(t *testing.T) {
	packet := func(body string) []byte {
		f := make([]byte, 42+len(body))
		f[12] = 8
		f[14] = 0x45
		binary.BigEndian.PutUint16(f[16:18], uint16(28+len(body)))
		f[23] = 17
		copy(f[26:30], []byte{192, 0, 2, 10})
		binary.BigEndian.PutUint16(f[34:36], 1900)
		binary.BigEndian.PutUint16(f[36:38], 1900)
		binary.BigEndian.PutUint16(f[38:40], uint16(8+len(body)))
		copy(f[42:], body)
		return f
	}
	s := Source{ID: "p", Site: "s", Domain: "d"}
	at := time.Now()
	a := DecodeFrame(packet("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:device1\r\nCACHE-CONTROL: max-age=120\r\n\r\n"), s, at)
	b := DecodeFrame(packet("NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:device1\r\nNTS: ssdp:byebye\r\n\r\n"), s, at.Add(time.Second))
	if len(a) != 1 || len(b) != 1 || a[0].Payload["service_type"] != b[0].Payload["service_type"] {
		t.Fatal("withdrawal service differs")
	}
	o, e := FromEvent(b[0])
	if e != nil || o.Current(at.Add(time.Second)) {
		t.Fatal("withdrawal active")
	}
}

func TestSSDPCarriesSenderMACForIdentityAssociation(t *testing.T) {
	body := "NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:gw\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: http://192.168.1.1:1900/igd.xml\r\n\r\n"
	packet := func(mac []byte, vlan bool) []byte {
		head := 14
		if vlan {
			head = 18
		}
		f := make([]byte, head+28+len(body))
		copy(f[6:12], mac)
		if vlan {
			binary.BigEndian.PutUint16(f[12:14], 0x8100)
			binary.BigEndian.PutUint16(f[14:16], 120)
		}
		binary.BigEndian.PutUint16(f[head-2:head], 0x0800)
		ip := f[head:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(28+len(body)))
		ip[9] = 17
		copy(ip[12:16], []byte{192, 168, 1, 1})
		binary.BigEndian.PutUint16(ip[20:22], 1900)
		binary.BigEndian.PutUint16(ip[22:24], 1900)
		binary.BigEndian.PutUint16(ip[24:26], uint16(8+len(body)))
		copy(ip[28:], body)
		return f
	}
	s := Source{ID: "p", Site: "s", Domain: "d"}
	for _, vlan := range []bool{false, true} {
		events := DecodeFrame(packet([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x77}, vlan), s, time.Now())
		if len(events) != 1 {
			t.Fatalf("vlan=%v: ssdp not decoded", vlan)
		}
		o, err := FromEvent(events[0])
		if err != nil || o.MAC != "00:11:22:33:44:77" || o.IP != "192.168.1.1" || o.DeviceType != "gateway" {
			t.Fatalf("vlan=%v: sender identity missing: %+v %v", vlan, o, err)
		}
	}
	events := DecodeFrame(packet(make([]byte, 6), false), s, time.Now())
	if len(events) != 1 || events[0].Subject["mac"] != "" {
		t.Fatalf("zero source MAC attributed: %+v", events)
	}
}
