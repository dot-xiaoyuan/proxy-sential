package devicesignal

import (
	"bufio"
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
	tcp[0], tcp[1], tcp[2], tcp[3], tcp[12], tcp[13] = 0xc3, 0x50, 0x01, 0xbb, 0x50, flags
	return frame
}

func TestFlowSYNFrameKeepsSourceAndObservedDestinationPort(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		value, ok := parseFlowSYNFrame(flowSYNFrame(tagged, 0x02))
		if !ok || value.SourceIP != netip.MustParseAddr("10.202.4.8") || value.DestinationPort != 443 {
			t.Fatalf("tagged=%t flow=%+v ok=%t", tagged, value, ok)
		}
	}
	if response, ok := parseFlowSYNFrame(flowSYNFrame(false, 0x12)); !ok || !response.Response {
		t.Fatal("SYN+ACK must be distinguished from an outbound connection attempt")
	}
	if _, ok := parseFlowSYNFrame(flowSYNFrame(false, 0x10)); ok {
		t.Fatal("ACK must not become an outbound connection attempt")
	}
}

func TestFlowSYNResponseRequiresMatchingFourTupleAndAcknowledgment(t *testing.T) {
	initial := flowSYNFrame(false, 0x02)
	tcp := initial[14+20:]
	tcp[0], tcp[1] = 0xc3, 0x50
	tcp[4], tcp[5], tcp[6], tcp[7] = 0, 0, 0, 42
	request, ok := parseFlowSYNFrame(initial)
	if !ok || request.Response || request.SourcePort != 50000 || request.Sequence != 42 {
		t.Fatalf("initial SYN parse: %+v %t", request, ok)
	}
	responseFrame := flowSYNFrame(false, 0x12)
	ip := responseFrame[14:]
	copy(ip[12:16], []byte{203, 0, 113, 9})
	copy(ip[16:20], []byte{10, 202, 4, 8})
	responseTCP := responseFrame[14+20:]
	responseTCP[0], responseTCP[1], responseTCP[2], responseTCP[3] = 0x01, 0xbb, 0xc3, 0x50
	responseTCP[8], responseTCP[9], responseTCP[10], responseTCP[11] = 0, 0, 0, 43
	response, ok := parseFlowSYNFrame(responseFrame)
	if !ok || !response.Response {
		t.Fatalf("SYN-ACK parse: %+v %t", response, ok)
	}
	matcher := newFlowSYNMatcher(2)
	now := time.Now().UTC()
	if !matcher.recordInitial(request, now) {
		t.Fatal("bounded matcher rejected first SYN")
	}
	if _, ok := matcher.matchResponse(response, now.Add(time.Second)); !ok {
		t.Fatal("exact reverse SYN-ACK was not matched")
	}
	if _, ok := matcher.matchResponse(response, now.Add(2*time.Second)); ok {
		t.Fatal("duplicate SYN-ACK counted again")
	}
	response.Acknowledgment++
	if _, ok := matcher.matchResponse(response, now.Add(3*time.Second)); ok {
		t.Fatal("wrong TCP acknowledgment counted")
	}
	matcher.recordInitial(request, now)
	response.Acknowledgment--
	if _, ok := matcher.matchResponse(response, now.Add(time.Minute)); ok {
		t.Fatal("stale SYN-ACK counted")
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

func TestFlowSYNBucketKeepsOneMatchedResponseEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flow-syn.jsonl")
	at := time.Date(2026, 11, 1, 0, 0, 30, 0, time.UTC)
	key := flowSYNKey{SourceIP: netip.MustParseAddr("10.202.4.8"), DestinationPort: 443}
	if err := writeFlowSYNBucket(path, "sensor-a", "bond0", "collector-a", nil, at,
		map[flowSYNKey]int{key: 3}, map[flowSYNKey]int{key: 2}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	items := map[string]normalized.Event{}
	for scanner.Scan() {
		var event normalized.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		items[event.SourceEventType] = event
		if _, retained := event.Flow["dst_ip"]; retained {
			t.Fatal("remote address leaked into durable response event")
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items["syn_attempt"].EventID != "" || items["syn_ack_observed"].EventID == "" {
		t.Fatalf("matched response must replace duplicate attempt evidence: %+v", items)
	}
	response := items["syn_ack_observed"]
	if response.Payload["connection_outcome"] != "syn_ack_observed" || response.Payload["observed_count"] != float64(2) || response.Flow["dst_port"] != float64(443) {
		t.Fatalf("response overstated or lost evidence: %+v", response)
	}
}
