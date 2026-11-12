package devicesignal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func fragmentedSADPFrames(body string) ([]byte, []byte) {
	frame := sadpFrame(body, "08:54:11:13:c1:84", true)
	const ethernetLength, fragmentBytes = 18, 1480
	udp := append([]byte(nil), frame[ethernetLength+20:]...)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	first := append([]byte(nil), frame[:ethernetLength+20+fragmentBytes]...)
	copy(first[ethernetLength+20:], udp[:fragmentBytes])
	ip := first[ethernetLength:]
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+fragmentBytes))
	binary.BigEndian.PutUint16(ip[4:6], 57195)
	binary.BigEndian.PutUint16(ip[6:8], 0x2000)
	last := append([]byte(nil), frame[:ethernetLength+20]...)
	last = append(last, udp[fragmentBytes:]...)
	ip = last[ethernetLength:]
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(last)-ethernetLength))
	binary.BigEndian.PutUint16(ip[4:6], 57195)
	binary.BigEndian.PutUint16(ip[6:8], fragmentBytes/8)
	return first, last
}

func observedGeometrySADP() string {
	// 204 read-only capture: UDP length 1627 = 8-byte header + 1619 XML bytes.
	// Child order mirrors the response; private device fields are synthetic.
	skeleton := `<ProbeMatch><Uuid>redacted</Uuid><Types>inquiry</Types><DeviceType>852122</DeviceType><DeviceDescription>DS-K1T6QT-F72M</DeviceDescription><DeviceSN>redacted</DeviceSN><CommandPort>8000</CommandPort><HttpPort>80</HttpPort><EHomeVer>1</EHomeVer><MAC>08-54-11-13-c1-84</MAC><IPv4Address>10.126.253.1</IPv4Address><IPv4SubnetMask>255.255.255.0</IPv4SubnetMask><IPv4Gateway>10.126.253.254</IPv4Gateway><Pad></Pad></ProbeMatch>`
	padding := 1619 - len(skeleton)
	return strings.Replace(skeleton, "<Pad></Pad>", "<Pad>"+strings.Repeat("x", padding)+"</Pad>", 1)
}

func TestSADPFragmentedResponseReassemblesBeforeClassification(t *testing.T) {
	// The 204 sample uses a 1500-byte first IPv4 fragment and a short last
	// fragment. Keep the real fragment geometry without retaining private XML.
	response := observedGeometrySADP()
	first, last := fragmentedSADPFrames(response)
	if len(first) != 1518 || len(last) != 185 {
		t.Fatalf("fixture does not match observed Ethernet frames: first=%d last=%d", len(first), len(last))
	}
	bucket := newCaptureBucket()
	bucket.addFrame(first, nil)
	if len(bucket.controls) != 0 {
		t.Fatal("partial SADP response became evidence")
	}
	bucket.addFrame(last, nil)
	if len(bucket.controls) != 1 {
		t.Fatalf("complete response produced %d observations", len(bucket.controls))
	}
	for _, signal := range bucket.controls {
		hash := sha256.Sum256([]byte(response))
		if signal.Kind != "sadp" || signal.Payload["product_model"] != "DS-K1T6QT-F72M" || signal.Payload["identity_status"] != "direct_l2" || signal.VLAN != 17 || signal.Payload["payload_sha256"] != hex.EncodeToString(hash[:]) {
			t.Fatalf("fragmented SADP lost attribution or packet reference: %+v", signal)
		}
	}
}

func TestSADPFragmentsRejectIncompleteAndOversizedDatagrams(t *testing.T) {
	response := observedGeometrySADP()
	first, last := fragmentedSADPFrames(response)
	for _, sample := range []struct {
		name        string
		first, last []byte
	}{
		{"last fragment only", nil, last},
		{"missing last fragment", first, nil},
		{"oversized udp length", func() []byte {
			v := append([]byte(nil), first...)
			binary.BigEndian.PutUint16(v[18+20+4:18+20+6], 9000)
			return v
		}(), last},
		{"inconsistent last fragment", first, func() []byte { v := append([]byte(nil), last...); v[len(v)-1] ^= 1; return v }()},
	} {
		t.Run(sample.name, func(t *testing.T) {
			bucket := newCaptureBucket()
			if sample.first != nil {
				bucket.addFrame(sample.first, nil)
			}
			if sample.last != nil {
				bucket.addFrame(sample.last, nil)
			}
			if len(bucket.controls) != 0 {
				t.Fatalf("invalid fragment sequence became evidence: %+v", bucket.controls)
			}
		})
	}
}
