package devicesignal

import (
	"encoding/binary"
	"net"
	"testing"
)

func buildDahuaFrame(srcMAC, srcIP, dstIP string, srcPort, dstPort uint16, body []byte) []byte {
	udpLen := 8 + len(body)
	ipLen := 20 + udpLen
	frame := make([]byte, 14+ipLen)
	hw, _ := net.ParseMAC(srcMAC)
	copy(frame[6:12], hw)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipLen))
	frame[23] = 17
	copy(frame[26:30], net.ParseIP(srcIP).To4())
	copy(frame[30:34], net.ParseIP(dstIP).To4())
	binary.BigEndian.PutUint16(frame[34:36], srcPort)
	binary.BigEndian.PutUint16(frame[36:38], dstPort)
	binary.BigEndian.PutUint16(frame[38:40], uint16(udpLen))
	copy(frame[42:], body)
	return frame
}

func wrapDHIPHeader(jsonBody string) []byte {
	hdr := make([]byte, 32)
	hdr[0] = 0x20
	copy(hdr[4:8], []byte("DHIP"))
	return append(hdr, []byte(jsonBody)...)
}

func TestParseDahuaDiscoveryDirectAndBoundaries(t *testing.T) {
	sample := `{"method":"client.notifyDevInfo","params":{"mac":"90:02:a9:12:34:56","deviceInfo":{"DeviceType":"DH-IPC-HFW2433M-I2","DeviceClass":"IPC","Vendor":"Dahua","IPv4Address":{"IPAddress":"10.20.2.15"}}}}`
	direct := buildDahuaFrame("90:02:a9:12:34:56", "10.20.2.15", "239.255.255.251", 37810, 37810, wrapDHIPHeader(sample))
	sig, ok := parseControlFrame(direct)
	if !ok {
		t.Fatal("expected direct Dahua discovery response to parse")
	}
	if sig.Kind != "dahua_discovery" || sig.MAC != "90:02:a9:12:34:56" || sig.Payload["product_model"] != "DH-IPC-HFW2433M-I2" || sig.Payload["identity_status"] != "direct_l2" {
		t.Fatalf("unexpected Dahua signal: %+v", sig)
	}

	// 跨三层 L2 不匹配时清除 signal.MAC
	routed := buildDahuaFrame("00:11:22:33:44:55", "10.20.2.15", "239.255.255.251", 37810, 37810, wrapDHIPHeader(sample))
	sigRouted, ok := parseControlFrame(routed)
	if !ok || sigRouted.MAC != "" || sigRouted.Payload["identity_status"] != "l2_mismatch" {
		t.Fatalf("routed Dahua must clear MAC and mark l2_mismatch: %+v ok=%v", sigRouted, ok)
	}

	// 探测请求必须被拒绝
	probe := `{"method":"DHDiscover.search","params":{"mac":"","uni":1}}`
	if _, ok := parseControlFrame(buildDahuaFrame("00:11:22:33:44:55", "10.20.2.99", "239.255.255.251", 55000, 37810, wrapDHIPHeader(probe))); ok {
		t.Fatal("DHDiscover.search probe must be rejected")
	}
}
