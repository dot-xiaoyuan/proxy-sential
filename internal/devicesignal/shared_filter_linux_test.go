//go:build linux

package devicesignal

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

func runSharedSignalFilter(t *testing.T, frame []byte) int {
	t.Helper()
	raw := make([]bpf.RawInstruction, len(sharedSignalSocketFilter))
	for index, instruction := range sharedSignalSocketFilter {
		raw[index] = bpf.RawInstruction{Op: instruction.Code, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	instructions, decoded := bpf.Disassemble(raw)
	if !decoded {
		t.Fatal("shared signal BPF contains an unsupported instruction")
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

func sharedFilterIPv4(flags byte, vlan bool) []byte {
	offset := 14
	frame := make([]byte, 256)
	frame[12], frame[13] = 0x08, 0x00
	if vlan {
		frame[12], frame[13], frame[16], frame[17] = 0x81, 0x00, 0x08, 0x00
		offset = 18
	}
	frame[offset], frame[offset+9] = 0x45, 6
	frame[offset+12], frame[offset+16] = 192, 198
	frame[offset+20+12], frame[offset+20+13] = 0x50, flags
	return frame
}

func sharedFilterIPv6(flags byte, vlan bool) []byte {
	offset := 14
	frame := make([]byte, 256)
	frame[12], frame[13] = 0x86, 0xdd
	if vlan {
		frame[12], frame[13], frame[16], frame[17] = 0x81, 0x00, 0x86, 0xdd
		offset = 18
	}
	frame[offset], frame[offset+6], frame[offset+7] = 0x60, 6, 64
	frame[offset+40+12], frame[offset+40+13] = 0x50, flags
	return frame
}

func TestSharedSignalFilterAcceptsOnlyInitialSYNAndTruncates(t *testing.T) {
	for _, frame := range [][]byte{
		sharedFilterIPv4(0x02, false), sharedFilterIPv4(0x02, true),
		sharedFilterIPv6(0x02, false), sharedFilterIPv6(0x02, true),
	} {
		if got := runSharedSignalFilter(t, frame); got != 128 {
			t.Fatalf("initial SYN accepted bytes=%d want=128", got)
		}
	}
	for _, frame := range [][]byte{
		sharedFilterIPv4(0x12, false), sharedFilterIPv4(0x10, false),
		sharedFilterIPv6(0x12, false), sharedFilterIPv6(0x10, true),
	} {
		if got := runSharedSignalFilter(t, frame); got != 0 {
			t.Fatalf("non-initial SYN accepted bytes=%d", got)
		}
	}
	udp := sharedFilterIPv4(0x02, false)
	udp[23] = 17
	if got := runSharedSignalFilter(t, udp); got != 0 {
		t.Fatalf("UDP packet accepted bytes=%d", got)
	}
}

func TestCaptureFiltersAreMutuallyExclusive(t *testing.T) {
	err := Run(context.Background(), Options{Interface: "ignored", Output: "ignored", SensorID: "test", RouterProtocolsOnly: true, SharedSignalsOnly: true})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("mutually exclusive filters were accepted: %v", err)
	}
}
