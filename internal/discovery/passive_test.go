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
