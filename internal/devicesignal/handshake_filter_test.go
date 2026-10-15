package devicesignal

import (
	"encoding/binary"
	"testing"
)

// runClassicBPF interprets the opcodes libpcap emits for this filter and returns the accept
// length (0 means reject).
func runClassicBPF(prog []bpfInsn, pkt []byte) uint32 {
	var a, x uint32
	var memory [16]uint32
	pc := 0
	load := func(off int, size int) (uint32, bool) {
		if off < 0 || off+size > len(pkt) {
			return 0, false
		}
		switch size {
		case 1:
			return uint32(pkt[off]), true
		case 2:
			return uint32(binary.BigEndian.Uint16(pkt[off:])), true
		}
		return binary.BigEndian.Uint32(pkt[off:]), true
	}
	for pc < len(prog) {
		in := prog[pc]
		pc++
		switch in.Code {
		case 0x28: // ldh abs
			v, ok := load(int(in.K), 2)
			if !ok {
				return 0
			}
			a = v
		case 0x30: // ldb abs
			v, ok := load(int(in.K), 1)
			if !ok {
				return 0
			}
			a = v
		case 0x20: // ld w abs
			v, ok := load(int(in.K), 4)
			if !ok {
				return 0
			}
			a = v
		case 0x48: // ldh ind
			v, ok := load(int(x+in.K), 2)
			if !ok {
				return 0
			}
			a = v
		case 0x50: // ldb ind
			v, ok := load(int(x+in.K), 1)
			if !ok {
				return 0
			}
			a = v
		case 0x40: // ld w ind
			v, ok := load(int(x+in.K), 4)
			if !ok {
				return 0
			}
			a = v
		case 0x60: // ld M[k]
			a = memory[in.K&15]
		case 0x61: // ldx M[k]
			x = memory[in.K&15]
		case 0x02: // st M[k] = A
			memory[in.K&15] = a
		case 0x03: // stx M[k] = X
			memory[in.K&15] = x
		case 0x07: // tax
			x = a
		case 0x87: // txa
			a = x
		case 0x0c: // add X
			a += x
		case 0xb1: // ldx msh
			v, ok := load(int(in.K), 1)
			if !ok {
				return 0
			}
			x = (v & 0x0f) * 4
		case 0x74: // rsh
			a >>= in.K
		case 0x54: // and
			a &= in.K
		case 0x64: // lsh
			a <<= in.K
		case 0x15: // jeq
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x45: // jset
			if a&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x05:
			pc += int(in.K)
		case 0x06: // ret
			return in.K
		default:
			return 0
		}
	}
	return 0
}

type uint16Insn struct {
	code   uint16
	jt, jf uint8
	k      uint32
}

// The verified program must accept exactly the frames the libpcap expression selects: both
// the plain and the VLAN-tagged ClientHello, the 0x16 client packet, and the HTTP request;
// it must reject bulk application data and other ports, plain or tagged.
func TestHandshakeProgramSelectsHandshakeFrames(t *testing.T) {
	mac := [6]byte{0x02, 0, 0, 0, 0, 0x77}
	ip := [4]byte{10, 0, 0, 77}
	base := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"client hello", buildTCPFrame(mac, ip, 443, clientHello("check.example", "h2")), true},
		{"client 0x16 record", buildTCPFrame(mac, ip, 443, []byte{0x16, 0x03, 0x03, 0, 1, 2}), true},
		{"bulk application data", buildTCPFrame(mac, ip, 443, []byte{0x17, 0x03, 0x03, 0, 5, 1, 2, 3, 4, 5}), false},
		{"http request", buildTCPFrame(mac, ip, 80, []byte("GET / HTTP/1.1\r\nHost: r.local\r\n\r\n")), true},
		{"other port", buildTCPFrame(mac, ip, 8443, clientHello("other.example", "")), false},
	}
	for _, c := range base {
		for _, tagged := range []bool{false, true} {
			frame := c.frame
			if tagged {
				frame = append(append(append([]byte{}, frame[:12]...), 0x81, 0x00, 0x00, 0x0a), frame[12:]...)
			}
			if got := runClassicBPF(handshakeProgram, frame) > 0; got != c.want {
				t.Fatalf("%s tagged=%t: accepted=%t want %t", c.name, tagged, got, c.want)
			}
		}
	}
}
