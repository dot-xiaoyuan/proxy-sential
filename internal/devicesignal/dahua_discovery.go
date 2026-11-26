package devicesignal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
)

// parseDahuaDiscovery 解析大华设备发现协议（UDP 37810，DHIP 32 字节头 + JSON 或纯 JSON 响应）。
// 仅接收设备主动通告或发现响应（如 client.notifyDevInfo / 带 deviceInfo 的响应），
// 拒绝 DHDiscover.search 探测请求，且不保留序列号或认证字段。
func parseDahuaDiscovery(ethernet ethernetFrame, source, destination string, payload []byte) (controlSignal, bool) {
	if len(payload) < 16 || len(payload) > 8192 {
		return controlSignal{}, false
	}
	// 查找 JSON 起始位置：标准大华 DHIP UDP 37810 响应在 32 字节头（0x20 0x00 0x00 0x00 + "DHIP"）之后为 JSON。
	jsonStart := -1
	if len(payload) > 32 && payload[0] == 0x20 && bytes.Equal(payload[4:8], []byte("DHIP")) {
		idx := bytes.IndexByte(payload[32:], '{')
		if idx >= 0 {
			jsonStart = 32 + idx
		}
	} else if payload[0] == '{' {
		jsonStart = 0
	}
	if jsonStart < 0 {
		return controlSignal{}, false
	}
	rawJSON := bytes.TrimRight(payload[jsonStart:], "\x00 \r\n\t")
	if len(rawJSON) < 2 || rawJSON[len(rawJSON)-1] != '}' {
		return controlSignal{}, false
	}
	var doc struct {
		Method string `json:"method"`
		Params struct {
			Mac        string `json:"mac"`
			DeviceInfo struct {
				DeviceType  string `json:"DeviceType"`
				DeviceClass string `json:"DeviceClass"`
				Vendor      string `json:"Vendor"`
				IPv4Address struct {
					IPAddress string `json:"IPAddress"`
				} `json:"IPv4Address"`
			} `json:"deviceInfo"`
		} `json:"params"`
		// 兼容扁平化旧版 JSON 响应
		Mac         string `json:"Mac"`
		DeviceType  string `json:"DeviceType"`
		Vendor      string `json:"Vendor"`
		IPv4Address struct {
			IPAddress string `json:"IPAddress"`
		} `json:"IPv4Address"`
	}
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		return controlSignal{}, false
	}
	// 明确拒绝探测请求
	if strings.EqualFold(strings.TrimSpace(doc.Method), "DHDiscover.search") {
		return controlSignal{}, false
	}
	model := cleanDahuaField(firstNonEmptyString(doc.Params.DeviceInfo.DeviceType, doc.DeviceType), 128)
	if model == "" {
		return controlSignal{}, false
	}
	vendor := cleanDahuaField(firstNonEmptyString(doc.Params.DeviceInfo.Vendor, doc.Vendor), 64)
	if vendor == "" {
		vendor = "Dahua"
	}
	claimedIP := strings.TrimSpace(firstNonEmptyString(doc.Params.DeviceInfo.IPv4Address.IPAddress, doc.IPv4Address.IPAddress))
	claimedMACRaw := strings.TrimSpace(firstNonEmptyString(doc.Params.Mac, doc.Mac))
	claimedMAC, macErr := net.ParseMAC(strings.ReplaceAll(claimedMACRaw, "-", ":"))
	parsedIP, ipErr := netip.ParseAddr(claimedIP)
	if macErr != nil || len(claimedMAC) != 6 || claimedMAC[0]&1 != 0 || claimedMAC.String() == "00:00:00:00:00:00" ||
		ipErr != nil || !parsedIP.Is4() || !parsedIP.IsGlobalUnicast() {
		return controlSignal{}, false
	}

	frameMAC := strings.ToLower(net.HardwareAddr(ethernet.source[:]).String())
	claimed := strings.ToLower(claimedMAC.String())
	status := "direct_l2"
	if claimedIP != source {
		status = "ip_mismatch"
	} else if frameMAC != claimed {
		status = "l2_mismatch"
	}

	signal := baseControlSignal("dahua_discovery", ethernet, source, destination)
	if status != "direct_l2" {
		signal.MAC = ""
	}
	digest := sha256.Sum256(payload)
	signal.Payload["is_response"] = true
	signal.Payload["message_type"] = "device_info"
	signal.Payload["product_model"] = model
	signal.Payload["manufacturer"] = vendor
	if class := cleanDahuaField(doc.Params.DeviceInfo.DeviceClass, 64); class != "" {
		signal.Payload["device_class"] = class
	}
	signal.Payload["claimed_ip"] = claimedIP
	signal.Payload["claimed_mac"] = claimed
	signal.Payload["l2_source_mac"] = frameMAC
	signal.Payload["identity_status"] = status
	signal.Payload["payload_sha256"] = hex.EncodeToString(digest[:])
	signal.Payload["ttl"] = 1800
	return signal, true
}

func firstNonEmptyString(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func cleanDahuaField(value string, limit int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > limit || strings.ContainsAny(trimmed, "\x00\r\n<>") {
		return ""
	}
	return trimmed
}
