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

func TestCaptureBucketControlOwnershipReplay(t *testing.T) {
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	forwarded := make([]byte, 14+20)
	copy(forwarded[6:12], mac)
	forwarded[12] = 8
	forwarded[14], forwarded[22], forwarded[23] = 0x45, 63, 6
	copy(forwarded[26:30], []byte{192, 168, 0, 82})
	copy(forwarded[30:34], []byte{8, 8, 8, 8})
	lldp := append([]byte{1, 0x80, 0xc2, 0, 0, 0x0e}, mac...)
	lldp = append(lldp, 0x88, 0xcc)
	lldp = append(lldp, 2, 7, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 4, 2, 5, '1', 6, 2, 0, 120, 10, 8, 'R', 'o', 'u', 't', 'e', 'r', '-', '1', 14, 4, 0, 20, 0, 20)
	explicit := append([]byte{}, lldp...)
	explicit = append(explicit, 16, 12, 5, 1, 192, 0, 2, 10, 2, 0, 0, 0, 1, 0, 0, 0)
	lldp = append(lldp, 0, 0)
	cdp := append([]byte{1, 0, 0x0c, 0xcc, 0xcc, 0xcc}, mac...)
	cdp = append(cdp, 0, 0)
	cdp = append(cdp, 0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0, 2, 120, 0, 0, 0, 1, 0, 12, 'R', 'o', 'u', 't', 'e', 'r', '-', '1')
	binary.BigEndian.PutUint16(cdp[12:14], uint16(len(cdp)-14))
	vrrp := make([]byte, 14+20+8)
	copy(vrrp[:6], []byte{1, 0, 0x5e, 0, 0, 18})
	copy(vrrp[6:12], mac)
	vrrp[12] = 8
	vrrp[14], vrrp[22], vrrp[23] = 0x45, 255, 112
	copy(vrrp[26:30], []byte{192, 0, 2, 1})
	copy(vrrp[30:34], []byte{224, 0, 0, 18})
	copy(vrrp[34:], []byte{0x21, 42, 110, 1, 0, 1, 0, 0})
	bucket := newCaptureBucket()
	for _, frame := range [][]byte{forwarded, lldp, explicit, cdp, vrrp} {
		bucket.addFrame(frame, nil)
	}
	if len(bucket.controls) != 4 {
		t.Errorf("lost control observations: count=%d want=4", len(bucket.controls))
	}
	for _, signal := range bucket.controls {
		if signal.Kind == "cdp" || signal.Kind == "lldp" && signal.Payload["management_address"] == nil {
			if signal.IP != "" {
				t.Errorf("forwarded client IP became control device identity: kind=%s ip=%s", signal.Kind, signal.IP)
			}
		} else if signal.Kind == "lldp" && signal.IP != "192.0.2.10" {
			t.Errorf("lost explicit LLDP management IP: %+v", signal)
		} else if signal.Kind == "vrrp" && signal.IP != "192.0.2.1" {
			t.Errorf("lost protocol source IP: %+v", signal)
		}
	}
	out := filepath.Join(t.TempDir(), "controls.jsonl")
	if err := writeControlBucket(out, "office", "mirror", "capture-replay", nil, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), bucket.controls); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	for i := 0; i < len(bucket.controls); i++ {
		var event normalized.Event
		if err = decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Subject["mac"] != "aa:bb:cc:dd:ee:ff" {
			t.Fatalf("lost MAC evidence: %+v", event.Subject)
		}
		if event.SourceEventType == "cdp" || event.SourceEventType == "lldp" && event.Payload["management_address"] == nil {
			if event.Subject["ip"] != nil || event.Flow["src_ip"] != nil {
				t.Errorf("standard event published inferred IP: %+v", event)
			}
		}
	}
	if path := os.Getenv("PROXY_SENTINEL_CAPTURE_REPLAY_OUTPUT"); path != "" && !t.Failed() {
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCaptureBucketBoundsNewPacketKeys(t *testing.T) {
	bucket := newCaptureBucket()
	for index := 0; index < maxPacketBucketKeys; index++ {
		bucket.packets[packetBucketKey{TTL: index}] = 1
	}
	frame := make([]byte, 14+20+20)
	frame[12], frame[13], frame[14], frame[22], frame[23] = 8, 0, 0x45, 64, 6
	copy(frame[26:30], []byte{192, 168, 0, 82})
	copy(frame[30:34], []byte{198, 51, 100, 1})
	frame[46], frame[47] = 0x50, 0x02
	bucket.addFrame(frame, nil)
	if len(bucket.packets) != maxPacketBucketKeys || bucket.droppedPacketKeys != 1 {
		t.Fatalf("packet key bound failed: keys=%d dropped=%d", len(bucket.packets), bucket.droppedPacketKeys)
	}
}
