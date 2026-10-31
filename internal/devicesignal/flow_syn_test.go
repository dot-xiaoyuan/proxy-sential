package devicesignal

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func flowSYNFrame(vlan bool, flags byte) []byte {
	offset := 14
	if vlan {
		offset = 18
	}
	frame := make([]byte, offset+20+20)
	frame[12], frame[13] = 0x08, 0x00
	if vlan {
		frame[12], frame[13], frame[16], frame[17] = 0x81, 0x00, 0x08, 0x00
	}
	ip := frame[offset : offset+20]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	copy(ip[12:16], []byte{10, 202, 4, 8})
	copy(ip[16:20], []byte{203, 0, 113, 9})
	tcp := frame[offset+20:]
	tcp[2], tcp[3], tcp[12], tcp[13] = 0x01, 0xbb, 0x50, flags
	return frame
}

func TestFlowSYNFrameKeepsSourceAndObservedDestinationPort(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		value, ok := parseFlowSYNFrame(flowSYNFrame(tagged, 0x02))
		if !ok || value.SourceIP != netip.MustParseAddr("10.202.4.8") || value.DestinationPort != 443 {
			t.Fatalf("tagged=%t flow=%+v ok=%t", tagged, value, ok)
		}
	}
	if _, ok := parseFlowSYNFrame(flowSYNFrame(false, 0x12)); ok {
		t.Fatal("SYN+ACK must not become an outbound connection attempt")
	}
	if _, ok := parseFlowSYNFrame(flowSYNFrame(false, 0x10)); ok {
		t.Fatal("ACK must not become an outbound connection attempt")
	}
}

func TestFlowSYNBucketWritesTraceableWeakStandardEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flow-syn.jsonl")
	at := time.Date(2026, 11, 1, 0, 0, 30, 0, time.UTC)
	key := flowSYNKey{SourceIP: netip.MustParseAddr("10.202.4.8"), DestinationPort: 443}
	if err := writeFlowSYNBucket(path, "sensor-a", "bond0", "collector-a", nil, at, map[flowSYNKey]int{key: 3}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event normalized.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "flow" || event.Source != "flow-syn-sidecar" || event.SourceEventType != "syn_attempt" || event.EventID == "" || event.Subject["ip"] != "10.202.4.8" || event.Flow["src_ip"] != "10.202.4.8" || event.Flow["proto"] != "tcp" || event.Flow["dst_port"] != float64(443) || event.Payload["observed_count"] != float64(3) || event.Payload["connection_outcome"] != "unverified" {
		t.Fatalf("flow event lost evidence or overstated outcome: %+v", event)
	}
}
