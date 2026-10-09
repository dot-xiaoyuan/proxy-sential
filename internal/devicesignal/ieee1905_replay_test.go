package devicesignal

import (
	"encoding/json"
	"testing"
)

func TestParseIEEE1905ClientAssociationEvent(t *testing.T) {
	frame := []byte{
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x13, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10, 0x89, 0x3a,
		0x00, 0x00, 0x00, 0x01, 0x26, 0x54, 0x00, 0xc0,
		0x01, 0x00, 0x06, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10,
		0x92, 0x00, 0x0d, 0x22, 0x07, 0x44, 0x95, 0x05, 0xf7, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x11, 0x80,
		0x00, 0x00, 0x00,
	}
	signals := parseControlFrames(frame)
	if len(signals) != 1 {
		t.Fatalf("unexpected IEEE 1905 signal count: %d", len(signals))
	}
	signal := signals[0]
	if signal.Kind != "ieee1905_client_association" || signal.MAC != "20:3a:eb:e9:de:10" {
		t.Fatalf("unexpected IEEE 1905 signal: %+v", signal)
	}
	if signal.Payload["client_mac"] != "22:07:44:95:05:f7" || signal.Payload["bssid"] != "20:3a:eb:e9:de:11" || signal.Payload["association_state"] != "joined" {
		t.Fatalf("unexpected client association payload: %+v", signal.Payload)
	}

	frame[len(frame)-4] = 0
	signals = parseControlFrames(frame)
	if len(signals) != 1 || signals[0].Payload["association_state"] != "left" {
		t.Fatalf("client departure was not preserved: %+v", signals)
	}
}

func TestParseIEEE1905AssociatedClientSnapshot(t *testing.T) {
	frame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x89, 0x3a,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x09, 0x00, 0x80,
		0x01, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x84, 0x00, 0x19, 0x01,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x00, 0x02,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x00, 0x2a,
		0x10, 0x20, 0x30, 0x40, 0x50, 0x61, 0x00, 0x07,
		0x00, 0x00, 0x00,
	}
	signals := parseControlFrames(frame)
	if len(signals) != 3 {
		t.Fatalf("unexpected topology snapshot signal count: %d", len(signals))
	}
	if signals[0].Payload["association_state"] != "joined" || signals[0].Payload["topology_snapshot"] != true || signals[0].Payload["association_age_seconds"] != 42 {
		t.Fatalf("unexpected topology snapshot payload: %+v", signals[0].Payload)
	}
	if signals[1].Payload["client_mac"] != "10:20:30:40:50:61" {
		t.Fatalf("second associated client missing: %+v", signals[1].Payload)
	}
}

func TestParseIEEE1905RejectsFragmentedCMDU(t *testing.T) {
	frame := []byte{
		0x01, 0x80, 0xc2, 0x00, 0x00, 0x13, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x10, 0x89, 0x3a,
		0x00, 0x00, 0x00, 0x01, 0x26, 0x54, 0x00, 0x40,
		0x92, 0x00, 0x0d, 0x22, 0x07, 0x44, 0x95, 0x05, 0xf7, 0x20, 0x3a, 0xeb, 0xe9, 0xde, 0x11, 0x80,
	}
	if signals := parseControlFrames(frame); len(signals) != 0 {
		t.Fatalf("fragmented CMDU was emitted without reassembly: %+v", signals)
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
