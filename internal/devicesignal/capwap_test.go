package devicesignal

import (
	"encoding/binary"
	"net"
	"testing"
)

func buildCAPWAPFrame(srcMAC, srcIP, dstIP string, srcPort, dstPort uint16, msgType uint32, vendorID uint32, model, baseMAC, wtpName string, dtls bool) []byte {
	var elems []byte
	if vendorID != 0 || model != "" || baseMAC != "" {
		var board []byte
		board = binary.BigEndian.AppendUint32(board, vendorID)
		if model != "" {
			board = binary.BigEndian.AppendUint16(board, 0)
			board = binary.BigEndian.AppendUint16(board, uint16(len(model)))
			board = append(board, []byte(model)...)
		}
		if baseMAC != "" {
			hw, _ := net.ParseMAC(baseMAC)
			board = binary.BigEndian.AppendUint16(board, 3)
			board = binary.BigEndian.AppendUint16(board, uint16(len(hw)))
			board = append(board, hw...)
		}
		elems = binary.BigEndian.AppendUint16(elems, 38)
		elems = binary.BigEndian.AppendUint16(elems, uint16(len(board)))
		elems = append(elems, board...)
	}
	if wtpName != "" {
		elems = binary.BigEndian.AppendUint16(elems, 45)
		elems = binary.BigEndian.AppendUint16(elems, uint16(len(wtpName)))
		elems = append(elems, []byte(wtpName)...)
	}

	// CAPWAP 8-byte header + 8-byte control header + elements
	capwap := make([]byte, 16+len(elems))
	if dtls {
		capwap[0] = 0x01
	} else {
		capwap[0] = 0x00
	}
	capwap[1] = 2 << 3 // HLEN = 2 (8 bytes)
	binary.BigEndian.PutUint32(capwap[8:12], msgType)
	capwap[12] = 1                                         // SeqNum
	binary.BigEndian.PutUint16(capwap[13:15], uint16(len(elems)+3)) // MsgElemLen
	copy(capwap[16:], elems)

	// Ethernet + IPv4 + UDP
	udpLen := 8 + len(capwap)
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
	copy(frame[42:], capwap)
	return frame
}

func TestParseCAPWAPDirectL2AndRoutedBoundary(t *testing.T) {
	directFrame := buildCAPWAPFrame("70:f9:6d:11:22:33", "10.20.1.10", "10.20.0.1", 52480, 5246, 1, 25506, "WA7338-HI", "70:f9:6d:11:22:33", "JXL-3F-AP02", false)
	sig, ok := parseControlFrame(directFrame)
	if !ok {
		t.Fatal("expected direct CAPWAP discovery request to parse")
	}
	if sig.Kind != "capwap" || sig.MAC != "70:f9:6d:11:22:33" || sig.IP != "10.20.1.10" {
		t.Fatalf("unexpected identity: %+v", sig)
	}
	if sig.Payload["manufacturer"] != "H3C" || sig.Payload["product_model"] != "WA7338-HI" || sig.Payload["name"] != "JXL-3F-AP02" || sig.Payload["identity_status"] != "direct_l2" {
		t.Fatalf("unexpected payload: %+v", sig.Payload)
	}

	// 跨三层转发时，以太网源 MAC 为网关 MAC，绝不能误绑为 AP 的 MAC
	routedFrame := buildCAPWAPFrame("00:aa:bb:cc:dd:ee", "10.20.1.10", "10.20.0.1", 52480, 5246, 3, 25506, "WA7338-HI", "70:f9:6d:11:22:33", "JXL-3F-AP02", false)
	routed, ok := parseControlFrame(routedFrame)
	if !ok || routed.MAC != "" || routed.Payload["identity_status"] != "l2_mismatch" || routed.Payload["claimed_mac"] != "70:f9:6d:11:22:33" {
		t.Fatalf("routed CAPWAP must clear signal.MAC and mark l2_mismatch, got %+v ok=%v", routed, ok)
	}

	// AC 响应报文（MsgType=2）和 DTLS 加密报文必须被拒绝
	acResp := buildCAPWAPFrame("00:aa:bb:cc:dd:ee", "10.20.0.1", "10.20.1.10", 5246, 52480, 2, 25506, "AC-1", "", "", false)
	if _, ok := parseControlFrame(acResp); ok {
		t.Fatal("AC response must not be classified as WTP AP")
	}
	dtlsFrame := buildCAPWAPFrame("70:f9:6d:11:22:33", "10.20.1.10", "10.20.0.1", 52480, 5246, 1, 25506, "WA7338-HI", "70:f9:6d:11:22:33", "AP", true)
	if _, ok := parseControlFrame(dtlsFrame); ok {
		t.Fatal("DTLS CAPWAP frame must be ignored")
	}
}

func TestParseCAPWAPEchoAndDataKeepAlive(t *testing.T) {
	// 运行期 Echo Request (MsgType=13) 应被识别为 ip_only 的 CAPWAP AP 活跃心跳
	echoReq := buildCAPWAPFrame("00:aa:bb:cc:dd:ee", "10.20.1.88", "10.20.0.1", 52480, 5246, 13, 0, "", "", "", false)
	sig, ok := parseControlFrame(echoReq)
	if !ok || sig.Kind != "capwap" || sig.MAC != "" || sig.IP != "10.20.1.88" || sig.Payload["message_type"] != "echo_request" {
		t.Fatalf("expected CAPWAP echo_request, got %+v ok=%v", sig, ok)
	}
	// Echo Response (MsgType=14) 必须拒绝
	echoResp := buildCAPWAPFrame("00:aa:bb:cc:dd:ee", "10.20.0.1", "10.20.1.88", 5246, 52480, 14, 0, "", "", "", false)
	if _, ok := parseControlFrame(echoResp); ok {
		t.Fatal("CAPWAP echo response must be rejected")
	}

	// UDP 5247 Data Keep-Alive (K=1, Session ID Type=35, Len=16)
	keepalive := make([]byte, 8+22)
	keepalive[0] = 0x00
	keepalive[1] = 2 << 3 // HLEN=8
	keepalive[3] = 0x08   // K=1
	binary.BigEndian.PutUint16(keepalive[8:10], 22)
	binary.BigEndian.PutUint16(keepalive[10:12], 35)
	binary.BigEndian.PutUint16(keepalive[12:14], 16)
	frame := buildDahuaFrame("00:aa:bb:cc:dd:ee", "10.20.1.89", "10.20.0.1", 52481, 5247, keepalive)
	ksig, ok := parseControlFrame(frame)
	if !ok || ksig.Kind != "capwap" || ksig.MAC != "" || ksig.IP != "10.20.1.89" || ksig.Payload["message_type"] != "data_keepalive" {
		t.Fatalf("expected CAPWAP data_keepalive, got %+v ok=%v", ksig, ok)
	}

	// 普通 UDP 5247 数据帧（K=0）必须被拒绝
	keepalive[3] = 0x00
	if _, ok := parseControlFrame(buildDahuaFrame("00:aa:bb:cc:dd:ee", "10.20.1.89", "10.20.0.1", 52481, 5247, keepalive)); ok {
		t.Fatal("non-keepalive CAPWAP data packet must be ignored")
	}
}
