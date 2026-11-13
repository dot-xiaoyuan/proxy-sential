//go:build linux

package devicesignal

import (
	"encoding/binary"
	"syscall"
	"testing"

	"golang.org/x/net/bpf"
)

func runRouterProtocolFilter(t *testing.T, frame []byte) int {
	t.Helper()
	return runRouterFilter(t, routerProtocolSocketFilter, frame)
}

func runRouterFilter(t *testing.T, filter []syscall.SockFilter, frame []byte) int {
	t.Helper()
	raw := make([]bpf.RawInstruction, len(filter))
	for index, instruction := range filter {
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

func TestRouterFilterSuppressesOnlyARPWhenOutputDisabled(t *testing.T) {
	withoutARP, err := routerProtocolFilterForARP(false)
	if err != nil {
		t.Fatal(err)
	}
	withARP, err := routerProtocolFilterForARP(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tags := range []int{0, 1, 2} {
		arp, _ := discoveryFrame(tags, 0x0806)
		if got := runRouterFilter(t, withoutARP, arp); got != 0 {
			t.Fatalf("disabled ARP with %d tags reached user space: %d", tags, got)
		}
		if got := runRouterFilter(t, withARP, arp); got == 0 {
			t.Fatalf("enabled ARP with %d tags was rejected", tags)
		}
		for _, protocol := range []struct {
			name  string
			frame []byte
		}{
			{"lldp", func() []byte {
				frame, _ := discoveryFrame(tags, 0x88cc)
				return frame
			}()},
			{"ieee1905", func() []byte {
				frame, _ := discoveryFrame(tags, 0x893a)
				return frame
			}()},
			{"ndp", func() []byte {
				frame, offset := discoveryFrame(tags, 0x86dd)
				frame[offset], frame[offset+6], frame[offset+40] = 0x60, 58, 135
				return frame
			}()},
			{"mdns", func() []byte {
				frame, offset := discoveryFrame(tags, 0x0800)
				frame[offset], frame[offset+9] = 0x45, 17
				binary.BigEndian.PutUint16(frame[offset+22:], 5353)
				return frame
			}()},
			{"dhcp", func() []byte {
				frame, offset := discoveryFrame(tags, 0x0800)
				frame[offset], frame[offset+9] = 0x45, 17
				binary.BigEndian.PutUint16(frame[offset+20:], 68)
				binary.BigEndian.PutUint16(frame[offset+22:], 67)
				return frame
			}()},
			{"ws-discovery", func() []byte {
				frame, offset := discoveryFrame(tags, 0x0800)
				frame[offset], frame[offset+9] = 0x45, 17
				binary.BigEndian.PutUint16(frame[offset+22:], 3702)
				return frame
			}()},
			{"bulk-https", func() []byte {
				frame, offset := discoveryFrame(tags, 0x0800)
				frame[offset], frame[offset+9] = 0x45, 6
				binary.BigEndian.PutUint16(frame[offset+22:], 443)
				return frame
			}()},
		} {
			before := runRouterFilter(t, withARP, protocol.frame)
			after := runRouterFilter(t, withoutARP, protocol.frame)
			if before != after {
				t.Fatalf("%s with %d tags changed by ARP switch: before=%d after=%d", protocol.name, tags, before, after)
			}
		}
	}
	if &withARP[0] != &routerProtocolSocketFilter[0] || &withoutARP[0] == &routerProtocolSocketFilter[0] {
		t.Fatal("disabled ARP filter changed the generated source filter")
	}
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
