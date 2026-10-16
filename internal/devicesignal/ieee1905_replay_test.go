package devicesignal

import (
	"encoding/json"
	"testing"
)

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
