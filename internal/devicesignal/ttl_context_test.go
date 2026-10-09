package devicesignal

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func ttlContextFrame(dst [4]byte, ttl, protocol byte, sourcePort, destinationPort uint16) []byte {
	frame := make([]byte, 14+20+20)
	frame[12] = 8
	frame[14] = 0x45
	frame[22] = ttl
	frame[23] = protocol
	copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1})
	copy(frame[26:30], []byte{192, 168, 0, 57})
	copy(frame[30:34], dst[:])
	binary.BigEndian.PutUint16(frame[34:36], sourcePort)
	binary.BigEndian.PutUint16(frame[36:38], destinationPort)
	return frame
}

func TestCaptureTTLContextRetainsBoundedScopeWithoutMerging(t *testing.T) {
	for _, tc := range []struct {
		name, scope      string
		dst              [4]byte
		proto            byte
		srcPort, dstPort uint16
		fragment         bool
	}{
		{"unicast", "unicast", [4]byte{198, 51, 100, 1}, 17, 50000, 443, false},
		{"multicast", "multicast", [4]byte{239, 255, 255, 250}, 17, 1900, 1900, false},
		{"broadcast", "broadcast", [4]byte{255, 255, 255, 255}, 17, 68, 67, false},
		{"mdns_unicast", "protocol_specific", [4]byte{198, 51, 100, 1}, 17, 5353, 50000, false},
		{"tcp_5353", "unicast", [4]byte{198, 51, 100, 1}, 6, 50000, 5353, false},
		{"later_udp_fragment", "unclassified", [4]byte{198, 51, 100, 1}, 17, 5353, 50000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bucket := newCaptureBucket()
			frame := ttlContextFrame(tc.dst, 64, tc.proto, tc.srcPort, tc.dstPort)
			if tc.fragment {
				frame[21] = 1
			}
			bucket.addFrame(frame, nil)
			out := filepath.Join(t.TempDir(), "events.jsonl")
			if err := writePacketBucketWithScope(out, "office", "mirror", "replay", nil, time.Now().UTC(), bucket.packets); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var event normalized.Event
			if err = json.Unmarshal(raw, &event); err != nil {
				t.Fatal(err)
			}
			if event.Flow["traffic_scope"] != tc.scope {
				t.Errorf("scope=%v want=%s", event.Flow["traffic_scope"], tc.scope)
			}
			if event.Payload["observed_count"] != float64(1) || event.Payload["ttl"] != float64(64) {
				t.Fatal("raw count/TTL lost", event)
			}
		})
	}
	bucket := newCaptureBucket()
	bucket.addFrame(ttlContextFrame([4]byte{198, 51, 100, 1}, 64, 17, 50000, 443), nil)
	bucket.addFrame(ttlContextFrame([4]byte{239, 255, 255, 250}, 64, 17, 1900, 1900), nil)
	if len(bucket.packets) != 2 {
		t.Errorf("unicast and multicast merged: %d", len(bucket.packets))
	}
	out := filepath.Join(t.TempDir(), "separate.jsonl")
	writePacketBucketWithScope(out, "office", "mirror", "replay", nil, time.Now().UTC(), bucket.packets)
	raw, _ := os.ReadFile(out)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	ids := map[string]bool{}
	for decoder.More() {
		var event normalized.Event
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if ids[event.EventID] {
			t.Error("different scopes have same event ID")
		}
		ids[event.EventID] = true
	}
}

func TestTTLContextDoesNotCreatePerDestinationBuckets(t *testing.T) {
	bucket := newCaptureBucket()
	for i := 0; i < 1000; i++ {
		bucket.addFrame(ttlContextFrame([4]byte{198, 51, byte(i / 250), byte(i%250 + 1)}, 64, 17, 50000, 443), nil)
	}
	if len(bucket.packets) != 1 {
		t.Fatalf("TTL cardinality grew with destination: %d", len(bucket.packets))
	}
	for _, count := range bucket.packets {
		if count != 1000 {
			t.Fatal("observed count lost", count)
		}
	}
}

func TestCaptureTTLContextReplayDoesNotCreateHostDivergence(t *testing.T) {
	bucket := newCaptureBucket()
	bucket.addFrame(ttlContextFrame([4]byte{198, 51, 100, 1}, 64, 17, 50000, 443), nil)
	bucket.addFrame(ttlContextFrame([4]byte{239, 255, 255, 250}, 1, 17, 1900, 1900), nil)
	bucket.addFrame(ttlContextFrame([4]byte{224, 0, 0, 251}, 255, 17, 5353, 5353), nil)
	out := filepath.Join(t.TempDir(), "context-replay.jsonl")
	at := time.Now().UTC().Truncate(time.Second)
	if err := writePacketBucketWithScope(out, "office", "mirror", "ttl-context-replay", nil, at, bucket.packets); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evidence.Analyze(bytes.NewReader(raw), evidence.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Evidence {
		if item.Type == "ttl_clusters" {
			t.Fatalf("protocol TTLs became host divergence: %+v", item)
		}
	}
	events := []normalized.Event{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for decoder.More() {
		var event normalized.Event
		if err = decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 3 {
		t.Fatal("raw observations removed", len(events))
	}
	if path := os.Getenv("PROXY_SENTINEL_TTL_CONTEXT_REPLAY_OUTPUT"); path != "" {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTTLContextUsesExplicitEthernetBroadcast(t *testing.T) {
	frame := ttlContextFrame([4]byte{192, 168, 0, 255}, 128, 17, 68, 67)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	value, ok := parsePacketFrame(frame)
	if !ok || value.TrafficScope != "broadcast" {
		t.Fatal("link broadcast context lost", value)
	}
}
