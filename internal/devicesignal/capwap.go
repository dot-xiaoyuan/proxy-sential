package devicesignal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
)

// capwapEnterpriseVendor 将常见的无线接入点 IANA 企业号映射为标准厂商名称。
func capwapEnterpriseVendor(enterprise uint32) string {
	switch enterprise {
	case 25506:
		return "H3C"
	case 4881:
		return "Ruijie"
	case 2011:
		return "Huawei"
	case 9:
		return "Cisco"
	case 14823:
		return "Aruba"
	case 25053:
		return "Ruckus"
	case 3902:
		return "ZTE"
	case 11863:
		return "TP-Link"
	default:
		return ""
	}
}

// parseCAPWAP 解析 RFC 5415 明文 CAPWAP 控制报文（UDP 目标端口 5246）。
// 仅接收由瘦 AP（WTP）发往无线控制器（AC）的 Discovery Request (1)、Join Request (3)
// 与 Configuration Status Request (5)；拒绝 DTLS 加密包与 AC 侧响应报文，不保留序列号或凭据。
func parseCAPWAP(ethernet ethernetFrame, source, destination string, payload []byte) (controlSignal, bool) {
	if len(payload) < 16 || len(payload) > 8192 {
		return controlSignal{}, false
	}
	// Preamble: 高 4 位为版本（0），低 4 位为类型（0 = 明文 CAPWAP，1 = DTLS 加密）。
	if payload[0] != 0x00 {
		return controlSignal{}, false
	}
	// Header Length: payload[1] 高 5 位，单位为 4 字节字，至少 8 字节。
	hlen := int(payload[1]>>3) * 4
	if hlen < 8 || hlen+8 > len(payload) {
		return controlSignal{}, false
	}
	// 忽略分片控制报文（F 位 = payload[3] & 0x80）。
	if payload[3]&0x80 != 0 {
		return controlSignal{}, false
	}
	ctrl := payload[hlen:]
	msgType := binary.BigEndian.Uint32(ctrl[0:4])
	var msgTypeName string
	switch msgType {
	case 1:
		msgTypeName = "discovery_request"
	case 3:
		msgTypeName = "join_request"
	case 5:
		msgTypeName = "config_status_request"
	case 13:
		msgTypeName = "echo_request"
	default:
		return controlSignal{}, false
	}
	// RFC 5415 Section 4.5: Msg Elem Length 包含 Flags (1B) + SeqNum/MsgElemLen 后字段，
	// 实际消息元素区从 ctrl[8:] 开始，长度不超过 len(ctrl)-8。
	declaredLen := int(binary.BigEndian.Uint16(ctrl[5:7]))
	if declaredLen < 3 {
		return controlSignal{}, false
	}
	elemBytes := ctrl[8:]
	if maxLen := declaredLen - 3; maxLen < len(elemBytes) {
		elemBytes = elemBytes[:maxLen]
	}
	if msgType == 13 {
		// Echo Request 为运行期瘦 AP 保活心跳（WTP -> AC），载荷极小且可不携带 Board Data。
		if declaredLen > 1024 || payload[3]&0x07 != 0 {
			return controlSignal{}, false
		}
		frameMAC := strings.ToLower(net.HardwareAddr(ethernet.source[:]).String())
		signal := baseControlSignal("capwap", ethernet, source, destination)
		signal.MAC = ""
		digest := sha256.Sum256(payload)
		signal.Payload["is_request"] = true
		signal.Payload["message_type"] = msgTypeName
		signal.Payload["identity_status"] = "ip_only"
		signal.Payload["l2_source_mac"] = frameMAC
		signal.Payload["payload_sha256"] = hex.EncodeToString(digest[:])
		signal.Payload["ttl"] = 1800
		return signal, true
	}

	var vendorID uint32
	manufacturer, model, wtpName, claimedMAC := "", "", "", ""
	hasWTPElement := false
	elemCount := 0
	for len(elemBytes) >= 4 {
		elemCount++
		if elemCount > 64 {
			return controlSignal{}, false
		}
		elemType := binary.BigEndian.Uint16(elemBytes[0:2])
		elemLen := int(binary.BigEndian.Uint16(elemBytes[2:4]))
		elemBytes = elemBytes[4:]
		if elemLen > len(elemBytes) {
			return controlSignal{}, false
		}
		val := elemBytes[:elemLen]
		elemBytes = elemBytes[elemLen:]
		switch elemType {
		case 38: // WTP Board Data (RFC 5415 Section 4.6.40)
			if len(val) < 4 {
				return controlSignal{}, false
			}
			hasWTPElement = true
			vendorID = binary.BigEndian.Uint32(val[0:4])
			if v := capwapEnterpriseVendor(vendorID); v != "" {
				manufacturer = v
			}
			sub := val[4:]
			subCount := 0
			for len(sub) >= 4 {
				subCount++
				if subCount > 16 {
					break
				}
				subType := binary.BigEndian.Uint16(sub[0:2])
				subLen := int(binary.BigEndian.Uint16(sub[2:4]))
				sub = sub[4:]
				if subLen > len(sub) {
					return controlSignal{}, false
				}
				subVal := sub[:subLen]
				sub = sub[subLen:]
				switch subType {
				case 0: // Board Model Number
					if cleaned := cleanCAPWAPText(subVal, 128); cleaned != "" {
						model = cleaned
					}
				case 3: // Base MAC Address
					if len(subVal) == 6 && subVal[0]&1 == 0 {
						mac := strings.ToLower(net.HardwareAddr(subVal).String())
						if mac != "00:00:00:00:00:00" {
							claimedMAC = mac
						}
					}
				}
			}
		case 39: // WTP Descriptor
			hasWTPElement = true
		case 45: // WTP Name
			hasWTPElement = true
			if cleaned := cleanCAPWAPText(val, 128); cleaned != "" {
				wtpName = cleaned
			}
		}
	}
	if !hasWTPElement {
		return controlSignal{}, false
	}

	frameMAC := strings.ToLower(net.HardwareAddr(ethernet.source[:]).String())
	status := "ip_only"
	if claimedMAC != "" {
		if frameMAC == claimedMAC {
			status = "direct_l2"
		} else {
			status = "l2_mismatch"
		}
	}
	signal := baseControlSignal("capwap", ethernet, source, destination)
	if status != "direct_l2" {
		signal.MAC = ""
	}
	digest := sha256.Sum256(payload)
	signal.Payload["is_request"] = true
	signal.Payload["message_type"] = msgTypeName
	signal.Payload["identity_status"] = status
	signal.Payload["l2_source_mac"] = frameMAC
	signal.Payload["payload_sha256"] = hex.EncodeToString(digest[:])
	signal.Payload["ttl"] = 1800
	if vendorID > 0 {
		signal.Payload["vendor_enterprise_id"] = int(vendorID)
	}
	if manufacturer != "" {
		signal.Payload["manufacturer"] = manufacturer
	}
	if model != "" {
		signal.Payload["product_model"] = model
	}
	if wtpName != "" {
		signal.Payload["name"] = wtpName
	}
	if claimedMAC != "" {
		signal.Payload["claimed_mac"] = claimedMAC
	}
	return signal, true
}

func cleanCAPWAPText(raw []byte, limit int) string {
	trimmed := strings.TrimRight(string(raw), "\x00")
	cleaned := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1
	}, trimmed))
	if cleaned == "" || len(cleaned) > limit || strings.ContainsAny(cleaned, "<>\r\n") {
		return ""
	}
	return cleaned
}

// parseCAPWAPDataKeepAlive 解析 RFC 5415 Section 4.4.2 的 CAPWAP 数据通道 Keep-Alive 报文（UDP 目标端口 5247）。
// 严格校验明文前导、K=1 标志位、保留位为 0 且仅包含合法的 Session ID (Type 35, Len 16) 元素，
// 拒绝一切普通无线业务封装帧，不保留会话 ID 原文（仅输出报文 SHA-256 摘要）。
func parseCAPWAPDataKeepAlive(ethernet ethernetFrame, source, destination string, payload []byte) (controlSignal, bool) {
	if len(payload) < 30 || len(payload) > 128 {
		return controlSignal{}, false
	}
	if payload[0] != 0x00 {
		return controlSignal{}, false
	}
	hlen := int(payload[1]>>3) * 4
	if hlen < 8 || hlen+22 > len(payload) {
		return controlSignal{}, false
	}
	// Byte 3: F(0x80) L(0x40) W(0x20) M(0x10) K(0x08) Flags(0x07)
	if payload[3]&0x80 != 0 || payload[3]&0x08 == 0 || payload[3]&0x07 != 0 {
		return controlSignal{}, false
	}
	body := payload[hlen:]
	msgElemLen := int(binary.BigEndian.Uint16(body[0:2]))
	if msgElemLen < 22 || msgElemLen > len(body) {
		return controlSignal{}, false
	}
	elemType := binary.BigEndian.Uint16(body[2:4])
	elemLen := int(binary.BigEndian.Uint16(body[4:6]))
	if elemType != 35 || elemLen != 16 || 6+elemLen > msgElemLen {
		return controlSignal{}, false
	}
	frameMAC := strings.ToLower(net.HardwareAddr(ethernet.source[:]).String())
	signal := baseControlSignal("capwap", ethernet, source, destination)
	signal.MAC = ""
	digest := sha256.Sum256(payload)
	signal.Payload["is_request"] = true
	signal.Payload["message_type"] = "data_keepalive"
	signal.Payload["identity_status"] = "ip_only"
	signal.Payload["l2_source_mac"] = frameMAC
	signal.Payload["payload_sha256"] = hex.EncodeToString(digest[:])
	signal.Payload["ttl"] = 1800
	return signal, true
}
