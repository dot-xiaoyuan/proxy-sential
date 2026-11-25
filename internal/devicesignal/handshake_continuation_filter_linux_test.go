//go:build linux

package devicesignal

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// The real kernel verifies every shard at the maximum configured size.
// A private AF_UNIX datagram pair exercises delivery without network I/O.
func TestContinuationFilterLinuxKernel(t *testing.T) {
	keys := make(map[handshakeKey]struct{})
	for i := 0; i < maxContinuationKeys; i++ {
		keys[handshakeKey{IP: netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}), MAC: [6]byte{2, 0, 0, 0, byte(i >> 8), byte(i)}}] = struct{}{}
	}
	programs, err := continuationFilterPrograms(keys)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	for i, p := range programs {
		if err := attachContinuationProgram(pair[1], p); err != nil {
			t.Fatalf("attach shard %d (%d insns): %v", i, len(p), err)
		}
		n := i * continuationKeysPerFilter
		frame := buildTCPFrame([6]byte{2, 0, 0, 0, byte(n >> 8), byte(n)}, [4]byte{192, 0, byte(n >> 8), byte(n)}, 443, []byte{0, 0, 1})
		for _, expect := range []bool{true, false} {
			if !expect {
				frame[6] ^= 4
			}
			if _, err := unix.Write(pair[0], frame); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(frame))
			size, _, err := unix.Recvfrom(pair[1], buf, 0)
			if expect && (err != nil || size != len(frame)) || !expect && err != unix.EAGAIN {
				t.Fatalf("shard %d accept=%t: size=%d err=%v", i, expect, size, err)
			}
		}
	}
}
