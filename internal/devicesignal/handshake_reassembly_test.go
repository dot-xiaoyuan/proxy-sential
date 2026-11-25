package devicesignal

import (
	"encoding/binary"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func helloTestFrame(k handshakeKey, seq uint32, p []byte) []byte {
	f := buildTCPFrame(k.MAC, k.IP.As4(), 443, p)
	binary.BigEndian.PutUint32(f[38:], seq)
	return f
}

func TestPriorityReassemblyCannotCreateActivityOrChangeOrdinarySamples(t *testing.T) {
	hello := clientHello("test.example", "h2")
	key := handshakeKey{IP: netip.MustParseAddr("192.0.2.1"), MAC: [6]byte{2, 0, 0, 0, 0, 1}}
	start := uint32(0xfffffff0)
	now := time.Now()
	for _, size := range []int{1, 5, 6, 40} {
		first := helloTestFrame(key, start, hello[:size])
		second := helloTestFrame(key, start+uint32(size), hello[size:52])
		third := helloTestFrame(key, start+52, hello[52:])
		full := helloTestFrame(key, start, hello)
		expected, ok := parseHandshakeFrame(full)
		if !ok {
			t.Fatal("invalid fixture")
		}
		b := newCaptureBucket()
		b.handshakeEnabled, b.handshakeCaptureV2 = true, true
		b.authenticatedRouters = map[handshakeKey]struct{}{key: {}}
		// Two sockets may be drained in either order. Reorder continuations,
		// repeat the first part and wrap TCP sequence space.
		for _, frame := range [][]byte{first, third, first, second} {
			b.helloReassembly.consume(frame, b.authenticatedRouters, now)
		}
		b.addFrame(first, nil)
		original := b.handshakes[key]
		hadActivity := original.activity != nil
		var at time.Time
		if hadActivity {
			at = original.activity.At
		}
		ordinary := key
		ordinary.MAC[5]++
		b.addFrame(helloTestFrame(ordinary, start, hello[:size]), nil)
		b.helloReassembly.consume(helloTestFrame(ordinary, start, hello[:size]), b.authenticatedRouters, now)
		b.helloReassembly.consume(helloTestFrame(ordinary, start+uint32(size), hello[size:]), b.authenticatedRouters, now)
		keys := b.selectHandshakes(300, now, nil)
		if len(keys) != 2 || original.count != 1 || original.truncated != 1 || b.helloReassembly.stats.Recovered != 1 || b.helloReassembly.stats.Started != 1 {
			t.Fatalf("split=%d, stats=%+v count=%d truncated=%d", size, b.helloReassembly.stats, original.count, original.truncated)
		}
		if hadActivity != (original.activity != nil) || (hadActivity && !at.Equal(original.activity.At)) {
			t.Fatalf("split=%d synthesized activity", size)
		}
		if len(b.handshakes[ordinary].samples) > 0 || b.handshakes[ordinary].truncated != 1 {
			t.Fatal("ordinary split produced a feature or lost its truncation")
		}
		if len(original.samples) != 2 || original.samples["ja3/"+expected.EventID].Value != expected.JA3 || original.samples["ja4/"+expected.EventID].Value != expected.JA4 {
			t.Fatalf("split=%d got %v want %v", size, original.samples, expected)
		}
	}
}

func TestPriorityReassemblyGapsBoundsAndConflict(t *testing.T) {
	k := handshakeKey{IP: netip.MustParseAddr("192.0.2.1"), MAC: [6]byte{2, 0, 0, 0, 0, 1}}
	keys := map[handshakeKey]struct{}{k: {}}
	at := time.Now()
	hello := clientHello("limits.example", "h2")
	first := helloTestFrame(k, 100, hello[:32])
	rest := helloTestFrame(k, 132, hello[32:])
	tests := []struct {
		name  string
		run   func(*helloReassembly)
		check func(helloReassemblyStats) bool
	}{
		{"missing primary", func(r *helloReassembly) { r.consume(first, keys, at); r.consume(rest, keys, at) }, func(s helloReassemblyStats) bool { return s.Unpaired == 1 }},
		{"expired", func(r *helloReassembly) {
			r.consume(first, keys, at)
			r.consume(rest, keys, at.Add(helloFlightTimeout))
		}, func(s helloReassemblyStats) bool { return s.Expired == 1 }},
		{"missing middle", func(r *helloReassembly) {
			r.consume(first, keys, at)
			r.consume(helloTestFrame(k, 140, hello[40:]), keys, at)
		}, func(s helloReassemblyStats) bool { return s.Incomplete == 1 }},
		{"conflicting overlap", func(r *helloReassembly) {
			r.consume(first, keys, at)
			r.consume(helloTestFrame(k, 127, []byte{1, 2, 3, 4}), keys, at)
			r.consume(rest, keys, at)
		}, func(s helloReassemblyStats) bool { return s.Conflicts == 1 }},
		{"oversized", func(r *helloReassembly) {
			p := slices.Clone(hello[:32])
			binary.BigEndian.PutUint16(p[3:5], 0xffff)
			r.consume(helloTestFrame(k, 100, p), keys, at)
		}, func(s helloReassemblyStats) bool { return s.Oversize == 1 }},
		{"key removed", func(r *helloReassembly) { r.consume(first, keys, at); r.consume(rest, nil, at) }, func(s helloReassemblyStats) bool { return s.Incomplete == 1 }},
		{"different VLAN", func(r *helloReassembly) {
			r.consume(first, keys, at)
			tag := append(append(slices.Clone(rest[:12]), 0x81, 0, 0, 1), rest[12:]...)
			r.consume(tag, keys, at)
		}, func(s helloReassemblyStats) bool { return s.Incomplete == 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var r helloReassembly
			tc.run(&r)
			r.apply(nil, nil, 4)
			if r.stats.Recovered != 0 || !tc.check(r.stats) {
				t.Fatalf("stats=%+v", r.stats)
			}
		})
	}
	var limited helloReassembly
	for i := 0; i < maxHelloFlights+1; i++ {
		f := slices.Clone(first)
		binary.BigEndian.PutUint16(f[34:36], uint16(1024+i))
		limited.consume(f, keys, at)
	}
	if limited.stats.Capacity != 1 || len(limited.active) != maxHelloFlights {
		t.Fatalf("in-flight ceiling lost: %+v", limited.stats)
	}
}

func TestReassemblyKeepsExistingFeatureBudgetAndOrder(t *testing.T) {
	// Recovery can run only after ordinary selection and sample allocation.
	at := time.Now()
	b := newCaptureBucket()
	b.handshakeEnabled, b.handshakeCaptureV2 = true, true
	k := handshakeKey{IP: netip.MustParseAddr("192.0.2.1"), MAC: [6]byte{2, 0, 0, 0, 0, 1}}
	b.authenticatedRouters = map[handshakeKey]struct{}{k: {}}
	p := clientHello("test.example", "h2")
	first := helloTestFrame(k, 101, p[:32])
	b.addFrame(first, nil)
	b.helloReassembly.consume(first, b.authenticatedRouters, at)
	b.helloReassembly.consume(helloTestFrame(k, 133, p[32:]), b.authenticatedRouters, at)
	s := b.handshakes[k]
	before := maps.Clone(s.samples)
	b.helloReassembly.apply(map[*handshakeSummary]bool{s: true}, b.handshakes, 0)
	if s.truncated != 1 || !maps.Equal(before, s.samples) || s.overflow != 0 || b.helloReassembly.stats.FeatureOmitted != 2 {
		t.Fatalf("recovery displaced existing evidence %+v", b.helloReassembly.stats)
	}
}
