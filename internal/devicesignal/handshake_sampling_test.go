package devicesignal

import (
	"encoding/json"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

// Exercise the filtered-socket input, the actual selector, and the serialized
// heartbeat. A MAC or an IP alone cannot attach another frame to an outlet.
func TestPriorityRouterCoverageExplainsMissingActivity(t *testing.T) {
	b := newCaptureBucket()
	b.handshakeEnabled, b.handshakeCaptureV2 = true, true
	b.authenticatedRouters = map[handshakeKey]struct{}{}
	keys := make([]handshakeKey, 8)
	for i := range keys {
		keys[i] = handshakeKey{IP: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), MAC: [6]byte{2, 0, 0, 0, 0, byte(i + 1)}}
		b.authenticatedRouters[keys[i]] = struct{}{}
	}
	send := func(k handshakeKey, port uint16, payload []byte, syn bool, vlan bool, clip int) {
		f := buildTCPFrame(k.MAC, k.IP.As4(), port, payload)
		if syn {
			f[14+20+13] = 2
		}
		if vlan {
			f = append(append(append([]byte{}, f[:12]...), 0x81, 0, 0, 2), f[12:]...)
		}
		if clip > 0 {
			f = f[:clip]
		}
		b.addFrame(f, nil)
	}
	impostor := keys[0]
	impostor.MAC = keys[1].MAC
	send(impostor, 80, nil, true, false, 0)
	send(keys[1], 443, []byte{22}, false, false, 0)
	send(keys[2], 443, []byte{23, 3, 3, 0}, false, false, 0)
	send(keys[3], 80, nil, true, false, 0)
	send(keys[3], 80, nil, true, true, 0)
	send(keys[4], 8080, nil, true, false, 0)
	send(keys[5], 8080, nil, true, false, 0)
	send(keys[6], 443, nil, false, false, 14+18)
	// The final priority key reaches the pre-aggregation cardinality cap.
	background := newHandshakeSummary()
	for n := 0; len(b.handshakes) < maxPacketBucketKeys; n++ {
		k := handshakeKey{IP: netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})}
		b.handshakes[k] = background
	}
	send(keys[7], 8080, nil, true, false, 0)

	at := time.Unix(9120, 0)
	kept := b.selectHandshakes(1, at, nil)
	stats := b.routerSamplingCoverage(kept, RouterSamplingSnapshot{LookupFailed: true, ReusedPreviousList: true})
	coverage := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: at, To: at.Add(30 * time.Second), KernelStatsKnown: true, Dropped: 4, ParseUnknown: b.handshakeParseFailures}
	path := filepath.Join(t.TempDir(), "coverage.jsonl")
	err := writeCaptureCoverageDocument(path, "sensor", "bond0", "instance", "handshake-sidecar", nil, captureCoverageDocument{CoverageV2: coverage, RouterSampling: &stats})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Payload struct {
			Document struct {
				sharedaccess.CoverageV2
				Sampling routerSamplingCoverage `json:"authenticated_router_sampling"`
			} `json:"capture_coverage"`
		} `json:"payload"`
	}
	if err = json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	got := event.Payload.Document.Sampling
	want := map[string]int{routerNoMatchingFrame: 1, routerParseIncomplete: 2, routerNoUsableActivity: 1, routerMixedVLAN: 1, routerOutputLimit: 1, routerKeyLimit: 1}
	if got.Keys != 8 || got.RetainedActivity != 1 || len(got.Missing) != 7 || !maps.Equal(got.Reasons, want) || !got.LookupFailed || !got.ReusedPreviousList || event.Payload.Document.CoverageV2 != coverage {
		t.Fatalf("incorrect persisted priority accounting: %+v", got)
	}
	outstanding := map[handshakeKey]string{
		keys[0]: routerNoMatchingFrame, keys[1]: routerParseIncomplete, keys[2]: routerNoUsableActivity,
		keys[3]: routerMixedVLAN, keys[4]: routerOutputLimit, keys[5]: routerOutputLimit,
		keys[6]: routerParseIncomplete, keys[7]: routerKeyLimit,
	}
	delete(outstanding, kept[0])
	for _, m := range got.Missing {
		hw, err := net.ParseMAC(m.MAC)
		if err != nil {
			t.Fatal(err)
		}
		k := handshakeKey{IP: netip.MustParseAddr(m.IP), MAC: [6]byte(hw)}
		if outstanding[k] != m.Reason {
			t.Fatalf("unexpected outlet/reason %+v", m)
		}
		delete(outstanding, k)
	}
	if len(outstanding) > 0 {
		t.Fatalf("outlets without a reason: %v", outstanding)
	}
	b.resetHandshakes()
	got = b.routerSamplingCoverage(nil, RouterSamplingSnapshot{})
	if got.Reasons[routerNoMatchingFrame] != len(keys) {
		t.Fatalf("prior-bucket reasons leaked: %+v", got)
	}
}
