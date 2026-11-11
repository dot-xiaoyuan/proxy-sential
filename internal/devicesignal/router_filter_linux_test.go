//go:build linux

package devicesignal

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

func runRouterProtocolFilter(t *testing.T, frame []byte) int {
	t.Helper()
	raw := make([]bpf.RawInstruction, len(routerProtocolSocketFilter))
	for index, instruction := range routerProtocolSocketFilter {
		raw[index] = bpf.RawInstruction{Op: instruction.Code, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	instructions, decoded := bpf.Disassemble(raw)
	if !decoded {
		t.Fatal("discovery protocol filter contains an unsupported instruction")
	}
	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := vm.Run(frame)
	if err != nil {
		t.Fatal(err)
	}
	return accepted
}

func discoveryFrame(tags int, etherType uint16) ([]byte, int) {
	offset := 14 + 4*tags
	frame := make([]byte, offset+96)
	for tag := 0; tag < tags; tag++ {
		binary.BigEndian.PutUint16(frame[12+tag*4:], 0x8100)
	}
	binary.BigEndian.PutUint16(frame[12+tags*4:], etherType)
	return frame, offset
}

func TestRouterProtocolFilterRetainsDeviceDiscoveryProtocols(t *testing.T) {
	for _, tags := range []int{0, 1, 2} {
		arp, _ := discoveryFrame(tags, 0x0806)
		if got := runRouterProtocolFilter(t, arp); got == 0 {
			t.Fatalf("ARP with %d tags was rejected", tags)
		}
		ndp, offset := discoveryFrame(tags, 0x86dd)
		ndp[offset], ndp[offset+6], ndp[offset+40] = 0x60, 58, 135
		if got := runRouterProtocolFilter(t, ndp); got == 0 {
			t.Fatalf("NDP with %d tags was rejected", tags)
		}
		ws, offset := discoveryFrame(tags, 0x0800)
		ws[offset], ws[offset+9] = 0x45, 17
		binary.BigEndian.PutUint16(ws[offset+22:], 3702)
		if got := runRouterProtocolFilter(t, ws); got == 0 {
			t.Fatalf("WS-Discovery with %d tags was rejected", tags)
		}
		sadp, offset := discoveryFrame(tags, 0x0800)
		sadp[offset], sadp[offset+9] = 0x45, 17
		binary.BigEndian.PutUint16(sadp[offset+20:], 37020)
		binary.BigEndian.PutUint16(sadp[offset+22:], 37020)
		if got := runRouterProtocolFilter(t, sadp); got == 0 {
			t.Fatalf("SADP with %d tags was rejected", tags)
		}
		continuation := append([]byte(nil), sadp...)
		binary.BigEndian.PutUint16(continuation[offset+6:], 1480/8)
		if got := runRouterProtocolFilter(t, continuation); got == 0 {
			t.Fatalf("SADP continuation with %d tags was rejected", tags)
		}
		mdns, offset := discoveryFrame(tags, 0x0800)
		mdns[offset], mdns[offset+9] = 0x45, 17
		binary.BigEndian.PutUint16(mdns[offset+22:], 5353)
		if got := runRouterProtocolFilter(t, mdns); got == 0 {
			t.Fatalf("mDNS with %d tags was rejected", tags)
		}
		bulk, offset := discoveryFrame(tags, 0x0800)
		bulk[offset], bulk[offset+9] = 0x45, 6
		binary.BigEndian.PutUint16(bulk[offset+22:], 443)
		if got := runRouterProtocolFilter(t, bulk); got != 0 {
			t.Fatalf("bulk HTTPS with %d tags was accepted", tags)
		}
	}
}
