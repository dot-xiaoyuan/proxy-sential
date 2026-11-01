package discovery

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func fragmentReplayFrames(v6 bool, tags int, body []byte) [][]byte {
	link := make([]byte, 14+4*tags)
	copy(link[6:12], []byte{2, 1, 2, 3, 4, 5})
	for i := 0; i < tags; i++ {
		binary.BigEndian.PutUint16(link[12+4*i:], 0x8100)
		binary.BigEndian.PutUint16(link[14+4*i:], uint16(100+i))
	}
	ether := uint16(0x0800)
	if v6 {
		ether = 0x86dd
	}
	binary.BigEndian.PutUint16(link[len(link)-2:], ether)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp, 1900)
	binary.BigEndian.PutUint16(udp[2:], 1900)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(body)))
	udp = append(udp, body...)
	frames := [][]byte{}
	for start := 0; start < len(udp); start += 64 {
		end := min(start+64, len(udp))
		more := end < len(udp)
		var header []byte
		if v6 {
			header = make([]byte, 48)
			header[0] = 0x60
			header[6] = 44
			header[7] = 64
			header[8] = 0xfd
			header[23] = 1
			header[24] = 0xfd
			header[39] = 2
			header[40] = 17
			binary.BigEndian.PutUint16(header[4:], uint16(8+end-start))
			bits := uint16(start)
			if more {
				bits |= 1
			}
			binary.BigEndian.PutUint16(header[42:], bits)
			binary.BigEndian.PutUint32(header[44:], 123)
		} else {
			header = make([]byte, 20)
			header[0] = 0x45
			header[8] = 64
			header[9] = 17
			copy(header[12:16], []byte{10, 1, 2, 3})
			copy(header[16:20], []byte{239, 255, 255, 250})
			binary.BigEndian.PutUint16(header[2:], uint16(20+end-start))
			binary.BigEndian.PutUint16(header[4:], 123)
			bits := uint16(start / 8)
			if more {
				bits |= 0x2000
			}
			binary.BigEndian.PutUint16(header[6:], bits)
		}
		frame := append(append([]byte(nil), link...), header...)
		frame = append(frame, udp[start:end]...)
		frames = append(frames, frame)
	}
	return frames
}
func TestDiscoveryFragmentReplayAcrossIPv4IPv6AndQinQ(t *testing.T) {
	body := []byte("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:replay-device\r\nCACHE-CONTROL: max-age=120\r\n\r\n")
	for _, v6 := range []bool{false, true} {
		for tags := 0; tags <= 2; tags++ {
			t.Run(fmt.Sprintf("v6=%t/tags=%d", v6, tags), func(t *testing.T) {
				frames := fragmentReplayFrames(v6, tags, body)
				var decoder FrameDecoder
				now := time.Now()
				source := Source{ID: "replay", Node: "sensor", Site: "test", Domain: "mirror", Address: "mirror0"}
				for i := len(frames) - 1; i >= 0; i-- {
					events := decoder.Decode(frames[i], source, now)
					if i != 0 {
						if len(events) != 0 {
							t.Fatal("partial datagram emitted")
						}
						continue
					}
					if len(events) != 1 {
						t.Fatalf("complete datagram missing, drops=%d", decoder.FragmentDrops)
					}
					o, err := FromEvent(events[0])
					if err != nil || o.Origin != "ssdp" || o.MAC != "" {
						t.Fatalf("bad identity: %+v %v", o, err)
					}
					want := []string{"", "100", "100/101"}[tags]
					if o.VLAN != want {
						t.Fatalf("scope %q want %q", o.VLAN, want)
					}
				}
			})
		}
	}
}
func TestDiscoveryRejectsOverlappingAndExpiredFragments(t *testing.T) {
	body := make([]byte, 160)
	for _, v6 := range []bool{false, true} {
		f := fragmentReplayFrames(v6, 2, body)
		now := time.Now()
		var d FrameDecoder
		d.Decode(f[0], Source{}, now)
		d.Decode(f[0], Source{}, now)
		if d.FragmentDrops != 1 {
			t.Fatalf("overlap accepted v6=%t", v6)
		}
		d.Decode(f[0], Source{}, now)
		d.Decode(f[1], Source{}, now.Add(11*time.Second))
		if d.FragmentDrops < 2 {
			t.Fatalf("expired fragment retained v6=%t", v6)
		}
	}
}

func TestFragmentExpiryBoundaryAndReorderedTimes(t *testing.T) {
	at := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	payload := make([]byte, 8)
	var d FrameDecoder
	// Arrival timestamps can move backwards; expiration must use the earliest
	// timestamp, rather than insertion order or the latest fragment arrival.
	d.fragment("recent", nil, payload, 8, true, 14, false, at.Add(5*time.Second))
	d.fragment("older", nil, payload, 8, true, 14, false, at)
	d.fragment("boundary", nil, payload, 8, true, 14, false, at.Add(10*time.Second))
	if len(d.fragments) != 3 || d.FragmentDrops != 0 {
		t.Fatal("exactly ten seconds expired a live group")
	}
	d.fragment("after", nil, payload, 8, true, 14, false, at.Add(10*time.Second+time.Nanosecond))
	if d.fragments["older"] != nil || d.fragments["recent"] == nil || d.FragmentDrops != 1 {
		t.Fatalf("wrong expiry order/drops: groups=%v drops=%d", d.fragments, d.FragmentDrops)
	}
}

func TestFragmentExpiryReclaimsFullCapacityWithoutChangingBounds(t *testing.T) {
	at := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	payload := make([]byte, 8)
	var d FrameDecoder
	for i := range 256 {
		d.fragment(fmt.Sprintf("orphan-%d", i), nil, payload, 8, true, 14, false, at)
	}
	d.fragment("overflow", nil, payload, 8, true, 14, false, at.Add(10*time.Second))
	if len(d.fragments) != 256 || d.FragmentDrops != 1 {
		t.Fatalf("capacity or exact boundary changed: %d %d", len(d.fragments), d.FragmentDrops)
	}
	d.fragment("renewed", nil, payload, 8, true, 14, false, at.Add(10*time.Second+time.Nanosecond))
	if len(d.fragments) != 1 || d.fragments["renewed"] == nil || d.FragmentDrops != 257 {
		t.Fatalf("expired groups not reclaimed: %d %d", len(d.fragments), d.FragmentDrops)
	}
}

func TestFragmentExpiryPreservesVLANIsolation(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		framesA := fragmentReplayFrames(v6, 2, make([]byte, 160))
		framesB := fragmentReplayFrames(v6, 2, make([]byte, 160))
		for _, f := range framesB {
			binary.BigEndian.PutUint16(f[18:20], 202)
		}
		var d FrameDecoder
		at := time.Now()
		if d.prepare(framesA[0], at) != nil {
			t.Fatal("partial A emitted")
		}
		for _, f := range framesB[1:] {
			if d.prepare(f, at) != nil {
				t.Fatal("different VLAN fragments merged")
			}
		}
		var completeA []byte
		for _, f := range framesA[1:] {
			completeA = d.prepare(f, at)
		}
		if completeA == nil {
			t.Fatalf("A missing v6=%t", v6)
		}
		if completeB := d.prepare(framesB[0], at); completeB == nil {
			t.Fatalf("out-of-order B missing v6=%t", v6)
		}
		if len(d.fragments) != 0 || d.FragmentDrops != 0 {
			t.Fatalf("completed groups retained/dropped: %d %d", len(d.fragments), d.FragmentDrops)
		}
	}
}

func TestFragmentExpiryIndexRemainsBoundedAfterCompletionAndRejection(t *testing.T) {
	var d FrameDecoder
	at := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	payload := make([]byte, 8)
	header := make([]byte, 34)
	check := func() {
		t.Helper()
		if len(d.fragmentExpiry) != len(d.fragments) || len(d.fragmentExpiry) > 256 {
			t.Fatalf("expiry metadata leaked: heap=%d groups=%d", len(d.fragmentExpiry), len(d.fragments))
		}
		for i, g := range d.fragmentExpiry {
			if g.expiryIndex != i || d.fragments[g.key] != g {
				t.Fatal("expiry index lost its live group")
			}
		}
	}
	for i := range 255 {
		d.fragment(fmt.Sprintf("orphan-%d", i), nil, payload, 8, true, 14, false, at.Add(time.Duration(i)*time.Millisecond))
	}
	check()
	for i := range 10000 {
		key := fmt.Sprintf("completed-%d", i)
		d.fragment(key, header, payload, 0, true, 14, false, at)
		check()
		if d.fragment(key, nil, payload, 8, false, 14, false, at) == nil {
			t.Fatal("complete datagram lost")
		}
		check()
		d.fragment(key, nil, payload, 8, true, 14, false, at)
		d.fragment(key, nil, payload, 8, true, 14, false, at) // overlap removes group and its expiry node
		check()
	}
	d.fragment("after-expiry", nil, payload, 8, true, 14, false, at.Add(time.Minute))
	check()
	if len(d.fragments) != 1 {
		t.Fatal("expiry left old metadata")
	}
}
