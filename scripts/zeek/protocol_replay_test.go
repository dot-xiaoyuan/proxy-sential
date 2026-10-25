package zeekvalidation

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/dns/dnsmessage"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

var sampleMAC = []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
var sampleSource = discovery.Source{ID: "replay", Node: "replay-node", Site: "replay-site", Domain: "replay-domain", Address: "bond0"}
var sampleTime = time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)

func ethernet(kind uint16, body []byte, tagged bool) []byte {
	frame := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, sampleMAC...)
	if tagged {
		frame = append(frame, 0x81, 0, 0, 20)
	}
	frame = binary.BigEndian.AppendUint16(frame, kind)
	return append(frame, body...)
}

func udpFrame(port uint16, body []byte, tagged bool) []byte {
	ip := make([]byte, 28)
	ip[0], ip[9] = 0x45, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(body)))
	copy(ip[12:16], net.ParseIP("10.1.2.50").To4())
	copy(ip[16:20], net.ParseIP("10.1.2.100").To4())
	binary.BigEndian.PutUint16(ip[20:22], port)
	binary.BigEndian.PutUint16(ip[22:24], port)
	binary.BigEndian.PutUint16(ip[24:26], uint16(8+len(body)))
	return ethernet(0x0800, append(ip, body...), tagged)
}

func replayOne(t *testing.T, frame []byte, protocol string) normalized.Event {
	t.Helper()
	decoder := discovery.FrameDecoder{}
	events := decoder.Decode(frame, sampleSource, sampleTime)
	if len(events) != 1 || events[0].SourceEventType != protocol {
		t.Fatalf("expected one %s event: %+v", protocol, events)
	}
	if _, err := discovery.FromEvent(events[0]); err != nil {
		t.Fatalf("event cannot become a discovery observation: %v", err)
	}
	if events[0].Subject["domain"] != sampleSource.Domain || events[0].Observer["interface"] != sampleSource.Address {
		t.Fatal("capture scope lost")
	}
	return events[0]
}

func TestNameProtocolResponsesAndQueries(t *testing.T) {
	encodedName := ""
	for _, value := range []byte(fmt.Sprintf("%-15s", "LAB-PC") + "\x00") {
		encodedName += string([]byte{'A' + value>>4, 'A' + value&15})
	}
	for _, test := range []struct {
		protocol, name, expected string
		port                     uint16
		kind                     dnsmessage.Type
		body                     dnsmessage.ResourceBody
	}{
		{"nbns", encodedName + ".", "LAB-PC", 137, 32, &dnsmessage.UnknownResource{Type: 32, Data: []byte{0, 0, 10, 1, 2, 9}}},
		{"llmnr", "printer.local.", "printer.local", 5355, dnsmessage.TypeA, &dnsmessage.AResource{A: [4]byte{10, 1, 2, 9}}},
	} {
		for _, tagged := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tagged=%v", test.protocol, tagged), func(t *testing.T) {
				message := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(test.name), Type: test.kind, Class: dnsmessage.ClassINET, TTL: 120}, Body: test.body}}}
				body, err := message.Pack()
				if err != nil {
					t.Fatal(err)
				}
				event := replayOne(t, udpFrame(test.port, body, tagged), test.protocol)
				if event.Subject["ip"] != "10.1.2.9" || event.Subject["mac"] != "" || event.Payload["name"] != test.expected {
					t.Fatalf("answer ownership or name incorrect: %+v", event)
				}
				message.Header.Response = false
				body, err = message.Pack()
				if err != nil {
					t.Fatal(err)
				}
				if events := discovery.DecodeFrame(udpFrame(test.port, body, tagged), sampleSource, sampleTime); len(events) != 0 {
					t.Fatal("query created device evidence")
				}
			})
		}
	}
}

func TestNeighborProtocolReplay(t *testing.T) {
	tlv := func(kind uint16, body []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, kind<<9|uint16(len(body))), body...)
	}
	lldp := tlv(1, append([]byte{4}, sampleMAC...))
	lldp = append(lldp, tlv(2, []byte{5, 'p', '1'})...)
	lldp = append(lldp, tlv(3, []byte{0, 120})...)
	lldp = append(lldp, tlv(5, []byte("LAB-SWITCH"))...)
	lldp = append(lldp, tlv(8, []byte{5, 1, 10, 1, 2, 9})...)
	lldp = append(lldp, 0, 0)
	cdp := []byte{0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0, 2, 120, 0, 0, 0, 1, 0, 12, 'R', 'o', 'u', 't', 'e', 'r', '-', '1'}
	for _, tagged := range []bool{false, true} {
		ll := replayOne(t, ethernet(0x88cc, lldp, tagged), "lldp")
		if ll.Subject["ip"] != "10.1.2.9" || ll.Subject["mac"] != "" || ll.Payload["name"] != "LAB-SWITCH" {
			t.Fatalf("LLDP should retain management address without binding Ethernet sender: %+v", ll)
		}
		frame := ethernet(uint16(len(cdp)), cdp, tagged)
		copy(frame[:6], []byte{1, 0, 0x0c, 0xcc, 0xcc, 0xcc})
		cd := replayOne(t, frame, "cdp")
		if cd.Subject["ip"] != "" || cd.Payload["system_name"] != "Router-1" {
			t.Fatalf("CDP should remain a neighbor clue without invented IP: %+v", cd)
		}
	}
}

func TestARPReplyAndRequestOwnership(t *testing.T) {
	body := []byte{0, 1, 8, 0, 6, 4, 0, 2}
	body = append(body, sampleMAC...)
	body = append(body, 10, 1, 2, 9, 0, 0, 0, 0, 0, 0, 10, 1, 2, 100)
	for _, tagged := range []bool{false, true} {
		for _, op := range []byte{1, 2} {
			body[7] = op
			event := replayOne(t, ethernet(0x0806, body, tagged), "arp")
			if event.Subject["ip"] != "10.1.2.9" || event.Payload["address_binding"] != (op == 2) {
				t.Fatalf("ARP attributed target or request as authoritative binding: %+v", event)
			}
		}
	}
}

func TestNDPAdvertisementBindingAndInvalidHopLimit(t *testing.T) {
	body := make([]byte, 40+32)
	body[0], body[6], body[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(body[4:6], 32)
	copy(body[8:24], net.ParseIP("fd00::9").To16())
	copy(body[24:40], net.ParseIP("ff02::1").To16())
	body[40] = 136
	copy(body[48:64], net.ParseIP("fd00::9").To16())
	body[64], body[65] = 2, 1
	copy(body[66:72], sampleMAC)
	for _, tagged := range []bool{false, true} {
		event := replayOne(t, ethernet(0x86dd, body, tagged), "ndp")
		if event.Subject["ip"] != "fd00::9" || event.Subject["mac"] != "02:11:22:33:44:55" || event.Payload["address_binding"] != true {
			t.Fatalf("NDP advertisement binding incorrect: %+v", event)
		}
		invalid := append([]byte(nil), body...)
		invalid[7] = 64
		if events := discovery.DecodeFrame(ethernet(0x86dd, invalid, tagged), sampleSource, sampleTime); len(events) != 0 {
			t.Fatal("off-link NDP admitted")
		}
		invalid = append([]byte(nil), body...)
		invalid[40] = 135
		event = replayOne(t, ethernet(0x86dd, invalid, tagged), "ndp")
		if event.Subject["mac"] != "" || event.Payload["address_binding"] != false {
			t.Fatal("NDP solicitation became address binding")
		}
	}
}

func TestSingleOwnerRejectsParallelZeekDiscoveryImports(t *testing.T) {
	config := discovery.DefaultCollectionConfig()
	for _, protocol := range []string{"dns_sd", "mdns", "nbns", "llmnr", "lldp", "cdp", "arp", "ndp"} {
		for _, source := range []string{"zeek", "device-signals", "passive"} {
			if config.IngestOwns(normalized.Event{Source: source, SourceEventType: protocol}) {
				t.Fatalf("generic ingester would duplicate %s from %s", protocol, source)
			}
		}
	}
}

func TestNamesBatchFilterDoesNotEnableUnrelatedProtocols(t *testing.T) {
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("tcpdump BPF compiler unavailable")
	}
	config := discovery.DefaultCollectionConfig()
	for at := range config.Protocols {
		config.Protocols[at].Enabled = strings.Contains("|dns_sd|ssdp|ws_discovery|nbns|llmnr|", "|"+config.Protocols[at].Protocol+"|")
	}
	pcap := make([]byte, 24)
	binary.LittleEndian.PutUint32(pcap, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(pcap[4:], 2)
	binary.LittleEndian.PutUint16(pcap[6:], 4)
	binary.LittleEndian.PutUint32(pcap[16:], 65535)
	binary.LittleEndian.PutUint32(pcap[20:], 1)
	path := filepath.Join(t.TempDir(), "empty.pcap")
	if err = os.WriteFile(path, pcap, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := exec.Command(tcpdump, "-ddd", "-r", path, discovery.CaptureFilterFor(config)).Output()
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(raw)
	var count int
	if _, err = fmt.Fscan(reader, &count); err != nil {
		t.Fatal(err)
	}
	instructions := make([]bpf.RawInstruction, count)
	for at := range instructions {
		if _, err = fmt.Fscan(reader, &instructions[at].Op, &instructions[at].Jt, &instructions[at].Jf, &instructions[at].K); err != nil {
			t.Fatal(err)
		}
	}
	assembly, all := bpf.Disassemble(instructions)
	if !all {
		t.Fatal("invalid BPF")
	}
	vm, err := bpf.NewVM(assembly)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{137, 5355, 5353, 1900, 3702, 53, 443, 161} {
		for _, tagged := range []bool{false, true} {
			got, err := vm.Run(udpFrame(port, nil, tagged))
			if err != nil || (got > 0) != (port != 53 && port != 443 && port != 161) {
				t.Fatalf("port=%d tagged=%v got=%d error=%v", port, tagged, got, err)
			}
		}
	}
}

func TestIoTCandidateCapacityDoesNotTruncate(t *testing.T) {
	for _, count := range []int{0, 1, 128, 129} {
		candidates := make([]discovery.ZeekCandidate, count)
		for at := range candidates {
			candidates[at].IP = fmt.Sprintf("10.0.0.%d", at+1)
		}
		filter, err := discovery.CandidateTCPFilter(candidates)
		if (err != nil) != (count > 128) {
			t.Fatalf("count=%d error=%v", count, err)
		}
		if count == 0 && filter != "ether[12:2]=0xffff" {
			t.Fatal("zero candidates widened capture")
		}
	}
}
