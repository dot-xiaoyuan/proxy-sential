package devicesignal

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

func TestIEEE1905CoverageRecordsMemberSnapshotAvailability(t *testing.T) {
	ethernet := []byte{0x01, 0x80, 0xc2, 0, 0, 0x13, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10, 0x89, 0x3a}
	bucket := newCaptureBucket()
	for i, message := range [][]byte{
		{0, 0, 0, 0, 0, 1, 0, 0x80, 0, 0, 0},
		{0, 0, 0, 2, 0, 2, 0, 0x80, 0, 0, 0},
		{0, 0, 0, 3, 0, 3, 0, 0x80, 0, 0, 0},
		{0, 0, 0, 3, 0, 4, 0, 0x80, 0x84, 0, 1, 0, 0, 0, 0},
		{0, 0, 0, 3, 0, 5, 1, 0x80},
		{0, 0, 0, 3, 0, 6, 0, 0x80, 0x84, 0, 10, 0},
	} {
		bucket.addFrame(append(append([]byte(nil), ethernet...), message...), nil)
		if i == 2 && (len(bucket.controls) != 1 || bucket.controlParseFailures != 0) {
			t.Fatal("a complete response with no member snapshot emitted evidence or changed coverage")
		}
	}
	want := ieee1905CaptureStats{Frames: 6, TopologyQueries: 1, TopologyResponses: 4, WithMemberSnapshot: 1, WithoutMemberSnapshot: 1, FragmentedResponses: 1, MalformedResponses: 1}
	if bucket.ieee1905 != want || bucket.controlParseFailures != 2 || len(bucket.controls) != 2 {
		t.Fatalf("unexpected diagnostic counts or coverage: got %+v, parse failures %d, controls %d", bucket.ieee1905, bucket.controlParseFailures, len(bucket.controls))
	}
	at := time.Unix(100, 0).UTC()
	coverage := sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: at, To: at.Add(30 * time.Second), KernelStatsKnown: true}
	output := filepath.Join(t.TempDir(), "packet.jsonl")
	if err := writeCaptureCoverageDocument(output, "sensor", "bond0", "instance", "packet-sidecar", nil, captureCoverageDocument{CoverageV2: coverage, IEEE1905: &bucket.ieee1905}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Payload struct {
			Coverage struct {
				sharedaccess.CoverageV2
				IEEE1905 ieee1905CaptureStats `json:"ieee1905"`
			} `json:"capture_coverage"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatal(err)
	}
	if got := event.Payload.Coverage; got.IEEE1905 != want || got.CoverageV2 != coverage || !got.Complete() {
		t.Fatalf("unexpected persisted diagnostics or coverage proof: %+v", got)
	}
}

func TestIEEE1905EmptySnapshotRetainsBSSScope(t *testing.T) {
	frame := []byte{
		0x01, 0x80, 0xc2, 0, 0, 0x13, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10, 0x89, 0x3a,
		0, 0, 0, 3, 0, 9, 0, 0x80,
		1, 0, 6, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10,
		0x84, 0, 9, 1, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x11, 0, 0,
		0, 0, 0,
	}
	signals := parseControlFrames(frame)
	if len(signals) != 1 || signals[0].Kind != "ieee1905_client_snapshot" {
		t.Fatalf("empty BSS snapshot discarded: %+v", signals)
	}
	raw, err := json.Marshal(signals[0].Payload["bss_snapshots"])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `[{"bssid":"20:3a:eb:e9:de:11","client_macs":[]}]` {
		t.Fatalf("empty snapshot scope lost: %s", raw)
	}
	// A truncated TLV sequence must never retire prior clients.
	if signals = parseControlFrames(frame[:len(frame)-3]); len(signals) != 0 {
		t.Fatalf("unterminated snapshot accepted: %+v", signals)
	}
	// Undeclared trailing bytes inside the associated-client TLV are malformed.
	frame[len(frame)-13] = 10
	frame = append(frame[:len(frame)-3], append([]byte{0x01}, frame[len(frame)-3:]...)...)
	if signals = parseControlFrames(frame); len(signals) != 0 {
		t.Fatalf("malformed snapshot accepted: %+v", signals)
	}
}

func TestIEEE1905UsesOriginALMACInsteadOfRelayMAC(t *testing.T) {
	frame := []byte{
		0x01, 0x80, 0xc2, 0, 0, 0x13, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10, 0x89, 0x3a,
		0, 0, 0, 1, 0, 9, 0, 0xc0,
		1, 0, 6, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x92, 0, 13, 0x22, 0x07, 0x44, 0x95, 0x05, 0xf7, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x11, 0x80,
		0, 0, 0,
	}
	signals := parseControlFrames(frame)
	if len(signals) != 1 || signals[0].MAC != "22:33:44:55:66:77" || signals[0].Payload["ethernet_source_mac"] != "20:3a:eb:e9:de:10" {
		t.Fatalf("relay MAC used as association owner: %+v", signals)
	}
}

func TestIEEE1905TopologyResponseUsesDeviceInformationALMAC(t *testing.T) {
	// The source of the unicast response is the transmitting interface.
	header := []byte{
		0x02, 0x11, 0x22, 0x33, 0x44, 0x10, 0x02, 0x11, 0x22, 0x33, 0x44, 0x01,
		0x88, 0xa8, 0, 20, 0x81, 0, 0, 42, 0x89, 0x3a,
		0, 0, 0, 3, 0, 9, 0, 0x80,
	}
	deviceInformation := []byte{
		0x02, 0x11, 0x22, 0x33, 0x44, 0x02, 2,
		0x02, 0x11, 0x22, 0x33, 0x44, 0x01, 0, 0, 0,
		0x02, 0x11, 0x22, 0x33, 0x44, 0x03, 1, 0, 10,
		0x02, 0x11, 0x22, 0x33, 0x44, 0x03, 0, 0, 0, 0,
	}
	snapshot := []byte{0x84, 0, 17, 1, 0x02, 0x11, 0x22, 0x33, 0x44, 0x03, 0, 1,
		0x02, 0x11, 0x22, 0x33, 0x44, 0x04, 0, 12, 0, 0, 0}
	for _, tt := range []struct {
		name  string
		value []byte
		extra []byte
		valid bool
	}{
		{name: "interface and AL MAC differ", value: deviceInformation, valid: true},
		{name: "consistent AL MAC TLV", value: deviceInformation, extra: []byte{1, 0, 6, 0x02, 0x11, 0x22, 0x33, 0x44, 0x02}, valid: true},
		{name: "conflicting AL MAC TLV", value: deviceInformation, extra: []byte{1, 0, 6, 0x02, 0x11, 0x22, 0x33, 0x44, 0x05}},
		{name: "duplicate device information", value: deviceInformation, extra: []byte{3, 0, 7, 0x02, 0x11, 0x22, 0x33, 0x44, 0x05, 0}},
		{name: "short device information", value: deviceInformation[:6]},
		{name: "missing second interface", value: deviceInformation[:16]},
		{name: "truncated media information", value: deviceInformation[:len(deviceInformation)-1]},
		{name: "trailing device information", value: append(append([]byte(nil), deviceInformation...), 0)},
		{name: "non-unicast AL MAC", value: []byte{1, 0, 0, 0, 0, 1, 0}},
		{name: "zero AL MAC", value: []byte{0, 0, 0, 0, 0, 0, 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			frame := append(append([]byte(nil), header...), 3)
			frame = binary.BigEndian.AppendUint16(frame, uint16(len(tt.value)))
			frame = append(frame, tt.value...)
			frame = append(frame, tt.extra...)
			frame = append(frame, snapshot...)
			signals, observation := parseControlFramesWithCoverage(frame)
			if !tt.valid {
				if len(signals) != 0 || observation.complete || observation.snapshot {
					t.Fatalf("invalid device information supplied membership evidence: signals=%+v observation=%+v", signals, observation)
				}
				return
			}
			if len(signals) != 2 || !observation.complete || !observation.snapshot ||
				signals[0].Kind != "ieee1905_client_association" || signals[1].Kind != "ieee1905_client_snapshot" {
				t.Fatalf("valid topology response lost membership evidence: signals=%+v observation=%+v", signals, observation)
			}
			for _, signal := range signals {
				if signal.MAC != "02:11:22:33:44:02" || signal.Payload["al_mac"] != signal.MAC ||
					signal.Payload["ethernet_source_mac"] != "02:11:22:33:44:01" || signal.VLAN != 20 {
					t.Fatalf("incorrect response owner or capture provenance: %+v", signal)
				}
			}
		})
	}
}

func TestIEEE1905CaptureCountsUnreassembledFragments(t *testing.T) {
	// An actual Ethernet IEEE 1905 fragment cannot supply a complete snapshot.
	frame := make([]byte, 22)
	frame[12], frame[13] = 0x89, 0x3a
	frame[16], frame[17] = 0, 3
	frame[20], frame[21] = 1, 0
	bucket := newCaptureBucket()
	bucket.addFrame(frame, nil)
	if bucket.controlParseFailures != 1 || len(bucket.controls) != 0 {
		t.Fatalf("fragment was treated as complete: %+v", bucket)
	}
}

func TestIEEE1905CompleteTopologyQueryDoesNotCreateCoverageGap(t *testing.T) {
	frame := []byte{
		0x01, 0x80, 0xc2, 0, 0, 0x13, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10, 0x89, 0x3a,
		0, 0, 0, 2, 0, 9, 0, 0x80,
		0, 0, 0,
	}
	bucket := newCaptureBucket()
	bucket.addFrame(frame, nil)
	if bucket.controlParseFailures != 0 || len(bucket.controls) != 0 {
		t.Fatalf("valid topology query affected measured coverage: parse failures=%d controls=%d", bucket.controlParseFailures, len(bucket.controls))
	}
	bucket.addFrame(frame[:len(frame)-1], nil)
	if bucket.controlParseFailures != 1 || len(bucket.controls) != 0 {
		t.Fatalf("truncated IEEE 1905 message escaped loss accounting: parse failures=%d controls=%d", bucket.controlParseFailures, len(bucket.controls))
	}
}
