package devicesignal

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func taggedARP(tags ...uint16) []byte {
	frame := make([]byte, 14+4*len(tags)+28)
	copy(frame[:6], []byte{255, 255, 255, 255, 255, 255})
	copy(frame[6:12], []byte{0, 17, 34, 51, 68, 85})
	for i, tag := range tags {
		binary.BigEndian.PutUint16(frame[12+4*i:], 0x8100)
		binary.BigEndian.PutUint16(frame[14+4*i:], tag)
	}
	binary.BigEndian.PutUint16(frame[12+4*len(tags):], 0x0806)
	copy(frame[14+4*len(tags):], []byte{0, 1, 8, 0, 6, 4, 0, 2, 0, 17, 34, 51, 68, 85, 10, 161, 255, 33, 0, 0, 0, 0, 0, 0, 10, 161, 255, 254})
	return frame
}

func TestControlAddressScopeSurvivesEventExport(t *testing.T) {
	for _, tc := range []struct {
		tags []uint16
		want string
	}{{nil, ""}, {[]uint16{4005}, "4005"}, {[]uint16{3191, 38}, "3191/38"}} {
		signal, ok := parseControlFrame(taggedARP(tc.tags...))
		if !ok {
			t.Fatal("valid ARP rejected")
		}
		path := filepath.Join(t.TempDir(), "events.jsonl")
		if err := writeControlBucket(path, "sensor", "mirror", "", nil, time.Now(), map[string]controlSignal{signal.key(): signal}); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var e normalized.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		got, _ := e.Payload["vlan"].(string)
		if got != tc.want || e.Subject["ip"] != "10.161.255.33" || e.Subject["mac"] != "00:11:22:33:44:55" {
			t.Fatalf("scope %q lost or ARP target promoted: %+v", tc.want, e)
		}
	}
}

func TestControlQinQScopesDoNotCoalesce(t *testing.T) {
	a, _ := parseControlFrame(taggedARP(3191, 24))
	b, _ := parseControlFrame(taggedARP(3191, 38))
	if a.key() == b.key() {
		t.Fatal("inner VLAN identities collapsed")
	}
}

func TestTaggedEmptyLLDPIsNotProductEvidence(t *testing.T) {
	frame := taggedARP(4005)
	binary.BigEndian.PutUint16(frame[16:], 0x88cc)
	frame[18], frame[19] = 0, 0
	if _, ok := parseControlFrame(frame[:20]); ok {
		t.Fatal("VLAN metadata was treated as a device announcement")
	}
}

func TestSADPFragmentsRemainSeparatedByInnerVLAN(t *testing.T) {
	first, last := fragmentedSADPFrames(observedGeometrySADP())
	stack := func(frame []byte, inner uint16) []byte {
		out := make([]byte, len(frame)+4)
		copy(out[:16], frame[:16])
		binary.BigEndian.PutUint16(out[16:], 0x8100)
		binary.BigEndian.PutUint16(out[18:], inner)
		copy(out[20:], frame[16:])
		return out
	}
	b := newCaptureBucket()
	b.addFrame(stack(first, 24), nil)
	b.addFrame(stack(last, 38), nil)
	if len(b.controls) != 0 {
		t.Fatal("different VLAN fragments became one product response")
	}
	b.addFrame(stack(last, 24), nil)
	if len(b.controls) != 1 {
		t.Fatal("same VLAN response did not finish")
	}
	for _, signal := range b.controls {
		if signal.Payload["vlan"] != "17/24" {
			t.Fatal("fragment reassembly lost QinQ scope")
		}
	}
}
