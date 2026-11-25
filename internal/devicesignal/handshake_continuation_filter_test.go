package devicesignal

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
)

func TestContinuationFilterAdmitsSecondSegment(t *testing.T) {
	key := handshakeKey{IP: netip.MustParseAddr("192.0.2.24"), MAC: [6]byte{2, 0, 0, 0, 0, 1}}
	raw := buildTCPFrame(key.MAC, key.IP.As4(), 443, []byte{0, 1, 4, 0, 0, 1})
	if runClassicBPF(outletHandshakeProgram, raw) != 0 {
		t.Fatal("main capture started receiving continuation-only data")
	}
	vms := continuationTestVMs(t, map[handshakeKey]struct{}{key: {}})
	check := func(name string, f []byte, want int) {
		t.Helper()
		got, e := vms[0].Run(f)
		if e != nil || got != want {
			t.Errorf("%s: got %d, want %d, err %v", name, got, want, e)
		}
	}
	check("untagged", raw, continuationSnaplen)
	withTags := func(tags ...byte) []byte {
		f := append([]byte{}, raw[:12]...)
		f = append(f, tags...)
		return append(f, raw[12:]...)
	}
	check("dot1q", withTags(0x81, 0, 0, 1), continuationSnaplen)
	check("qinq", withTags(0x88, 0xa8, 0, 2, 0x81, 0, 0, 1), continuationSnaplen)
	check("third tag", withTags(0x88, 0xa8, 0, 3, 0x88, 0xa8, 0, 2, 0x81, 0, 0, 1), 0)
	withOptions := append([]byte{}, raw[:14+20]...)
	withOptions = append(withOptions, 1, 1, 1, 0)
	withOptions = append(withOptions, raw[14+20:14+40]...)
	withOptions = append(withOptions, 1, 1, 1, 0)
	withOptions = append(withOptions, raw[14+40:]...)
	withOptions[14] = 0x46
	withOptions[14+24+12] = 6 << 4
	binary.BigEndian.PutUint16(withOptions[16:], uint16(len(withOptions)-14))
	check("IP and TCP options", withOptions, continuationSnaplen)
	for name, mutate := range map[string]func([]byte){
		"nonpriority IP":                   func(f []byte) { f[14+15]++ },
		"nonpriority MAC":                  func(f []byte) { f[11]++ },
		"IPv6":                             func(f []byte) { f[12] = 0x86; f[13] = 0xdd },
		"UDP":                              func(f []byte) { f[14+9] = 17 },
		"IP fragment":                      func(f []byte) { f[14+6] = 0x20 },
		"port 80":                          func(f []byte) { binary.BigEndian.PutUint16(f[14+20+2:], 80) },
		"Ethernet padding after empty ACK": func(f []byte) { binary.BigEndian.PutUint16(f[14+2:], 40) },
		"short IP header":                  func(f []byte) { f[14] = 0x44 },
		"short TCP header":                 func(f []byte) { f[14+20+12] = 4 << 4 },
	} {
		f := append([]byte{}, raw...)
		mutate(f)
		check(name, f, 0)
	}
}

func continuationTestVMs(t *testing.T, keys map[handshakeKey]struct{}) []*bpf.VM {
	t.Helper()
	programs, err := continuationFilterPrograms(keys)
	if err != nil {
		t.Fatal(err)
	}
	var vms []*bpf.VM
	for _, p := range programs {
		if len(p) > 4096 {
			t.Fatalf("oversized classic BPF program: %d", len(p))
		}
		vm, e := bpf.NewVM(p)
		if e != nil {
			t.Fatal(e)
		}
		vms = append(vms, vm)
	}
	return vms
}

func TestContinuationFilterShardsAllPriorityKeys(t *testing.T) {
	for _, sameIP := range []bool{false, true} {
		keys := make(map[handshakeKey]struct{}, maxContinuationKeys)
		for i := 0; i < maxContinuationKeys; i++ {
			ip := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
			if sameIP {
				ip = netip.MustParseAddr("198.51.100.1")
			}
			keys[handshakeKey{IP: ip, MAC: [6]byte{2, 0, 0, 0, byte(i >> 8), byte(i)}}] = struct{}{}
		}
		vms := continuationTestVMs(t, keys)
		for k := range keys {
			frame := buildTCPFrame(k.MAC, k.IP.As4(), 443, []byte{1})
			accepted := 0
			for _, vm := range vms {
				v, err := vm.Run(frame)
				if err != nil {
					t.Fatal(err)
				}
				if v != 0 {
					accepted++
				}
			}
			if accepted != 1 {
				t.Fatalf("same IP=%t: outlet %+v accepted by %d shards", sameIP, k, accepted)
			}
		}
	}
	tooMany := make(map[handshakeKey]struct{})
	for i := 0; i <= maxContinuationKeys; i++ {
		k := handshakeKey{IP: netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}), MAC: [6]byte{2, 0, 0, 0, 0, 1}}
		tooMany[k] = struct{}{}
	}
	if programs, err := continuationFilterPrograms(tooMany); err == nil || len(programs) != 0 {
		t.Fatal("oversized priority list did not fail closed")
	}
	if programs, err := continuationFilterPrograms(nil); err != nil || len(programs) != 0 {
		t.Fatal("empty list opened sockets")
	}
}
