package devicesignal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/net/bpf"
)

const (
	continuationSnaplen = (16 << 10) + 256 // bounded TLS record plus link, IP and TCP headers
	// At most ten instructions per outlet, plus the fixed protocol checks,
	// below Linux's 4096-instruction limit. A full 2048-outlet list fits
	// on eight disjoint sockets. This also bounds the larger translated
	// program charged against the kernel per-socket option-memory limit.
	continuationKeysPerFilter = 256
	maxContinuationKeys       = 2048
)

// Each socket sees only TCP/443 payload from its precise IP/MAC pairs.
// Copies are consumed solely by the bounded ClientHello reconstruction path.
func continuationFilterPrograms(keys map[handshakeKey]struct{}) ([][]bpf.Instruction, error) {
	if len(keys) > maxContinuationKeys {
		return nil, fmt.Errorf("continuation filter: %d outlets exceed the limit of %d", len(keys), maxContinuationKeys)
	}
	sorted := make([]handshakeKey, 0, len(keys))
	for key := range keys {
		if !key.IP.Is4() || key.IP.IsUnspecified() || key.IP.IsMulticast() || key.MAC == [6]byte{} || key.MAC[0]&1 != 0 {
			return nil, fmt.Errorf("continuation filter: invalid IPv4 outlet")
		}
		sorted = append(sorted, key)
	}
	slices.SortFunc(sorted, func(a, b handshakeKey) int {
		if cmp := a.IP.Compare(b.IP); cmp != 0 {
			return cmp
		}
		return bytes.Compare(a.MAC[:], b.MAC[:])
	})
	var programs [][]bpf.Instruction
	for batch := range slices.Chunk(sorted, continuationKeysPerFilter) {
		prog := continuationTCPPrefix()
		programs = append(programs, appendContinuationOutlets(prog, batch))
	}
	return programs, nil
}

// Leave A holding the source IPv4 address. X advances past zero, one or
// two VLAN tags and the variable-length IP and TCP headers. Require payload
// according to IPv4 total length, so link-layer padding never admits an ACK.
func continuationTCPPrefix() []bpf.Instruction {
	var prog []bpf.Instruction
	var ipv4Jumps []int
	for depth := 0; depth <= 2; depth++ {
		prog = append(prog, bpf.LoadConstant{Dst: bpf.RegX, Val: uint32(14 + 4*depth)}, bpf.LoadAbsolute{Off: uint32(12 + 4*depth), Size: 2})
		ipv4Jumps = append(ipv4Jumps, len(prog))
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800})
		if depth < 2 {
			prog = append(prog,
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8100, SkipTrue: 2},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x88a8, SkipTrue: 1})
		}
		prog = append(prog, bpf.RetConstant{})
	}
	for _, pc := range ipv4Jumps {
		prog[pc] = bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: uint8(len(prog) - pc - 1)}
	}
	return append(prog,
		bpf.StoreScratch{Src: bpf.RegX, N: 0},                                    // start of IP
		bpf.LoadIndirect{Off: 2, Size: 2}, bpf.StoreScratch{Src: bpf.RegA, N: 1}, // IP total length
		bpf.LoadIndirect{Off: 9, Size: 1}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 1}, bpf.RetConstant{},
		bpf.LoadIndirect{Off: 6, Size: 2}, bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x3fff, SkipFalse: 1}, bpf.RetConstant{},
		bpf.LoadIndirect{Off: 0, Size: 1}, bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: 0x45, SkipTrue: 1}, bpf.RetConstant{},
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 0x4f, SkipFalse: 1}, bpf.RetConstant{},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 15}, bpf.ALUOpConstant{Op: bpf.ALUOpShiftLeft, Val: 2},
		bpf.ALUOpX{Op: bpf.ALUOpAdd}, bpf.TAX{}, // start of TCP
		bpf.LoadIndirect{Off: 2, Size: 2}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 443, SkipTrue: 1}, bpf.RetConstant{},
		bpf.LoadIndirect{Off: 12, Size: 1}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0}, bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2},
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: 20, SkipTrue: 1}, bpf.RetConstant{},
		bpf.ALUOpX{Op: bpf.ALUOpAdd}, bpf.LoadScratch{Dst: bpf.RegX, N: 0}, bpf.ALUOpX{Op: bpf.ALUOpSub}, bpf.TAX{}, // IP + TCP header lengths
		bpf.LoadScratch{Dst: bpf.RegA, N: 1}, bpf.JumpIfX{Cond: bpf.JumpGreaterThan, SkipTrue: 1}, bpf.RetConstant{},
		// Load the Ethernet source once. Scratch reads in the outlet table
		// avoid replicating the kernel's packet-load sequence for every MAC.
		bpf.LoadAbsolute{Off: 6, Size: 4}, bpf.StoreScratch{Src: bpf.RegA, N: 2},
		bpf.LoadAbsolute{Off: 10, Size: 2}, bpf.StoreScratch{Src: bpf.RegA, N: 3},
		bpf.LoadScratch{Dst: bpf.RegX, N: 0}, bpf.LoadIndirect{Off: 12, Size: 4},
	)
}

// Binary-search distinct IPs before reading the source MAC. Each subtree
// terminates in accept/reject. JA can cross the 8-bit conditional jump limit.
func appendContinuationOutlets(p []bpf.Instruction, keys []handshakeKey) []bpf.Instruction {
	if keys[0].IP != keys[len(keys)-1].IP {
		pivot := keys[len(keys)/2].IP
		if pivot == keys[0].IP {
			// Keep all MAC aliases of the first IP together.
			for _, key := range keys {
				if key.IP != pivot {
					pivot = key.IP
					break
				}
			}
		}
		mid, _ := slices.BinarySearchFunc(keys, pivot, func(k handshakeKey, ip netip.Addr) int { return k.IP.Compare(ip) })
		addr := pivot.As4()
		p = append(p, bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: binary.BigEndian.Uint32(addr[:]), SkipFalse: 1})
		jump := len(p)
		p = appendContinuationOutlets(append(p, bpf.Jump{}), keys[:mid])
		p[jump] = bpf.Jump{Skip: uint32(len(p) - jump - 1)}
		return appendContinuationOutlets(p, keys[mid:])
	}
	addr := keys[0].IP.As4()
	p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: binary.BigEndian.Uint32(addr[:]), SkipTrue: 1}, bpf.RetConstant{})
	for _, key := range keys {
		p = append(p,
			bpf.LoadScratch{Dst: bpf.RegA, N: 2}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: binary.BigEndian.Uint32(key.MAC[:4]), SkipFalse: 3},
			bpf.LoadScratch{Dst: bpf.RegA, N: 3}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(binary.BigEndian.Uint16(key.MAC[4:])), SkipFalse: 1},
			bpf.RetConstant{Val: continuationSnaplen})
	}
	return append(p, bpf.RetConstant{})
}
