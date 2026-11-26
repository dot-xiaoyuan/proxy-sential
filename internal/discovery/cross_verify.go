package discovery

import (
	"slices"
	"strings"
)

// CrossVerificationInput 汇总来自多个独立被动信源的当前观测维度，用于多源交叉确认。
// 本结构只承载结构化摘要，不持有原始报文文档，不替代 V8 硬件规则单源强确认。
type CrossVerificationInput struct {
	DHCPVendorClass       string
	DHCPRequestedOptions  string
	DHCPCandidateType     string
	Vendor                string
	Brand                 string
	SNIBrandHint          string
	SNIEcosystems         []string
	ObservedResponsePorts []string
	UserAgents            []string
	Protocols             []string
}

// CrossVerificationResult 表示多源交叉确认的裁决结果。
// 只有当 >=2 个独立信源指向同一规范品类且零冲突时，Status 才为 "cross_verified"。
type CrossVerificationResult struct {
	Status             string   `json:"status,omitempty"`
	DeviceType         string   `json:"device_type,omitempty"`
	RuleID             string   `json:"rule_id,omitempty"`
	IndependentSources []string `json:"independent_sources,omitempty"`
	Explanation        string   `json:"explanation,omitempty"`
	ConflictingTypes   []string `json:"conflicting_types,omitempty"`
}

// EvaluateCrossVerification 执行多源交叉确认评估。
// 规则约束：
// 1. 每条交叉确认规则必须包含至少 2 个独立维度的信号互证；
// 2. 端口信号仅接受响应端口（服务端端口或 CAPWAP 隧道控制口），防止普通客户端浏览被误判；
// 3. 若不同独立规则指向多个互斥设备类型，直接输出 conflict，绝不强行取胜。
func EvaluateCrossVerification(in CrossVerificationInput) CrossVerificationResult {
	vendorLower := strings.ToLower(strings.TrimSpace(in.Vendor + " " + in.Brand + " " + in.SNIBrandHint))
	dhcpVendorLower := strings.ToLower(strings.TrimSpace(in.DHCPVendorClass))

	portSet := make(map[string]bool, len(in.ObservedResponsePorts))
	for _, port := range in.ObservedResponsePorts {
		if trimmed := strings.ToLower(strings.TrimSpace(port)); trimmed != "" {
			portSet[trimmed] = true
		}
	}
	ecoSet := make(map[string]bool, len(in.SNIEcosystems))
	for _, eco := range in.SNIEcosystems {
		if trimmed := strings.ToLower(strings.TrimSpace(eco)); trimmed != "" {
			ecoSet[trimmed] = true
		}
	}
	if sniBrand := strings.ToLower(strings.TrimSpace(in.SNIBrandHint)); sniBrand != "" {
		ecoSet[sniBrand] = true
	}

	type matchCandidate struct {
		deviceType  string
		ruleID      string
		sources     []string
		explanation string
	}
	matches := []matchCandidate{}

	// 1. 无线接入点：DHCP Option 138 (CAPWAP AC) 或 AP 候选 + CAPWAP 5246/5247 端口互证
	hasOption138AP := strings.EqualFold(in.DHCPCandidateType, "access_point") ||
		PassiveDHCPClientCandidate(in.DHCPVendorClass, "", in.DHCPRequestedOptions) == "access_point"
	hasCAPWAPPort := portSet["udp/5246"] || portSet["udp/5247"]
	if hasOption138AP && hasCAPWAPPort {
		matches = append(matches, matchCandidate{
			deviceType:  "access_point",
			ruleID:      "cross:ap-dhcp138-capwap",
			sources:     []string{"dhcp_option_138", "port:udp/5246_5247"},
			explanation: "DHCP Option 138（CAPWAP AC）与 CAPWAP 控制端口（UDP 5246/5247）独立互证为无线接入点",
		})
	}

	// 2. 安防监控摄像机：海康/大华厂商 OUI 或云生态 + 专有响应端口（8000/554/37777）互证
	isHik := strings.Contains(vendorLower, "hikvision") || ecoSet["hikvision"]
	isDahua := strings.Contains(vendorLower, "dahua") || ecoSet["dahua"]
	if isHik && (portSet["tcp/8000"] || portSet["tcp/554"]) {
		portTag := "port:tcp/554"
		if portSet["tcp/8000"] {
			portTag = "port:tcp/8000"
		}
		matches = append(matches, matchCandidate{
			deviceType:  "camera",
			ruleID:      "cross:camera-hikvision-port",
			sources:     []string{"vendor_or_sni:hikvision", portTag},
			explanation: "海康威视厂商/平台线索与视频监控服务响应端口独立互证为摄像机/监控设备",
		})
	}
	if isDahua && (portSet["tcp/37777"] || portSet["udp/37777"] || portSet["tcp/554"]) {
		portTag := "port:tcp/554"
		if portSet["tcp/37777"] || portSet["udp/37777"] {
			portTag = "port:37777"
		}
		matches = append(matches, matchCandidate{
			deviceType:  "camera",
			ruleID:      "cross:camera-dahua-port",
			sources:     []string{"vendor_or_sni:dahua", portTag},
			explanation: "大华厂商/平台线索与监控服务响应端口独立互证为摄像机/监控设备",
		})
	}

	// 3. 网络打印机：打印厂商 OUI/DHCP 候选 + JetDirect 9100 或 IPP 631 响应端口互证
	paddedVendor := " " + vendorLower + " "
	isPrinterVendor := strings.EqualFold(in.DHCPCandidateType, "printer") ||
		strings.Contains(vendorLower, "hewlett") || strings.Contains(paddedVendor, " hp ") || strings.EqualFold(strings.TrimSpace(in.Brand), "hp") ||
		strings.Contains(vendorLower, "canon") || strings.Contains(vendorLower, "brother") || strings.Contains(vendorLower, "epson") ||
		strings.Contains(vendorLower, "ricoh") || strings.Contains(vendorLower, "kyocera") || strings.Contains(vendorLower, "xerox")
	if isPrinterVendor && (portSet["tcp/9100"] || portSet["tcp/631"]) {
		portTag := "port:tcp/631"
		if portSet["tcp/9100"] {
			portTag = "port:tcp/9100"
		}
		matches = append(matches, matchCandidate{
			deviceType:  "printer",
			ruleID:      "cross:printer-vendor-port",
			sources:     []string{"vendor_or_dhcp:printer", portTag},
			explanation: "打印厂商/DHCP 线索与网络打印服务端口（TCP 9100/631）独立互证为打印机",
		})
	}

	// 4. Windows 桌面终端：DHCP MSFT 5.0 + Windows 专属系统遥测/更新 SNI 或 Microsoft NCSI/CryptoAPI UA 互证
	hasWindowsUA := false
	for _, ua := range in.UserAgents {
		lowerUA := strings.ToLower(ua)
		if strings.Contains(lowerUA, "microsoft ncsi") || strings.Contains(lowerUA, "microsoft-cryptoapi") ||
			strings.Contains(lowerUA, "microsoft-delivery-optimization") || strings.Contains(lowerUA, "windows nt") {
			hasWindowsUA = true
			break
		}
	}
	if strings.HasPrefix(dhcpVendorLower, "msft ") && (ecoSet["windows"] || hasWindowsUA) {
		secondSource := "ua:windows_system"
		if ecoSet["windows"] {
			secondSource = "sni:windows_system"
		}
		matches = append(matches, matchCandidate{
			deviceType:  "desktop",
			ruleID:      "cross:desktop-windows-dhcp-telemetry",
			sources:     []string{"dhcp:msft", secondSource},
			explanation: "DHCP MSFT 5.0 与 Windows 系统专有服务/UA 独立互证为个人电脑",
		})
	}

	// 5. 移动终端：Android/HarmonyOS DHCP + 移动厂商专有连通性 SNI 或移动 Dalvik/iPhone UA 互证
	isMobileDHCP := strings.HasPrefix(dhcpVendorLower, "android-dhcp-") ||
		strings.HasPrefix(dhcpVendorLower, "huawei:android:") ||
		strings.HasPrefix(dhcpVendorLower, "huawei:openharmony:") ||
		(strings.HasPrefix(dhcpVendorLower, "dhcpcd-1") && !strings.Contains(dhcpVendorLower, "linux"))
	hasMobileUA := false
	for _, ua := range in.UserAgents {
		lowerUA := strings.ToLower(ua)
		if strings.Contains(lowerUA, "dalvik/") || strings.Contains(lowerUA, "liveio_android") ||
			strings.Contains(lowerUA, "android") || strings.Contains(lowerUA, "iphone") {
			hasMobileUA = true
			break
		}
	}
	if isMobileDHCP && (ecoSet["huawei"] || ecoSet["vivo"] || hasMobileUA) && !strings.EqualFold(in.DHCPCandidateType, "tablet") {
		secondSource := "ua:mobile_client"
		if ecoSet["huawei"] || ecoSet["vivo"] {
			secondSource = "sni:mobile_connectivity"
		}
		matches = append(matches, matchCandidate{
			deviceType:  "mobile",
			ruleID:      "cross:mobile-dhcp-ecosystem",
			sources:     []string{"dhcp:mobile_os", secondSource},
			explanation: "移动端 DHCP 指纹与手机厂商连通性/客户端特征独立互证为移动终端",
		})
	}

	if len(matches) == 0 {
		return CrossVerificationResult{}
	}
	distinctTypes := []string{}
	for _, m := range matches {
		if !slices.Contains(distinctTypes, m.deviceType) {
			distinctTypes = append(distinctTypes, m.deviceType)
		}
	}
	if len(distinctTypes) > 1 {
		slices.Sort(distinctTypes)
		return CrossVerificationResult{
			Status:           "conflict",
			ConflictingTypes: distinctTypes,
			Explanation:      "多源交叉确认存在互斥类型冲突，需保留原始证据待核查",
		}
	}
	winner := matches[0]
	return CrossVerificationResult{
		Status:             "cross_verified",
		DeviceType:         winner.deviceType,
		RuleID:             winner.ruleID,
		IndependentSources: winner.sources,
		Explanation:        winner.explanation,
	}
}

// IsL3ManagedEntity 判断一个无物理 MAC 的三层地址实体是否具备已验证的受管网元自报证据（如 SNMP 交换机、SIP 话机）。
func IsL3ManagedEntity(item DeviceView) bool {
	if strings.TrimSpace(item.MAC) != "" || len(item.Addresses) == 0 {
		return false
	}
	for _, clue := range item.ProductClues {
		if clue.ProductStatus == "identified" && clue.Type != "" &&
			(clue.Attribution == "response_ip" || clue.Attribution == "request_ip") {
			return true
		}
	}
	return false
}

// crossVerifyDeviceView 汇总单页设备视图上的当前非撤销观测维度，执行有界内存内多源交叉确认。
// 绝不替代硬件规则单源强确认，也不执行额外数据库查询。
func crossVerifyDeviceView(view DeviceView) *CrossVerificationResult {
	in := CrossVerificationInput{
		Vendor:            view.Manufacturer,
		Brand:             view.Manufacturer,
		DHCPCandidateType: view.CandidateDeviceType,
		Protocols:         view.Protocols,
	}
	for _, obs := range view.Observations {
		if obs.Withdrawn {
			continue
		}
		p := obs.Evidence.Payload
		if obs.Origin == "dhcp" || obs.Origin == "dhcp_client" {
			if vc := str(p, "vendor_class"); vc != "" && in.DHCPVendorClass == "" {
				in.DHCPVendorClass = vc
			}
			if ro := str(p, "requested_options"); ro != "" && in.DHCPRequestedOptions == "" {
				in.DHCPRequestedOptions = ro
			}
			if dc := str(p, "dhcp_candidate_type"); dc != "" && in.DHCPCandidateType == "" {
				in.DHCPCandidateType = dc
			}
		}
		if obs.Origin == "capwap" {
			in.ObservedResponsePorts = append(in.ObservedResponsePorts, "udp/5246")
		}
		if obs.Origin == "dahua_discovery" {
			in.ObservedResponsePorts = append(in.ObservedResponsePorts, "udp/37777")
			in.SNIEcosystems = append(in.SNIEcosystems, "Dahua")
		}
		if obs.Origin == "ipp" {
			in.ObservedResponsePorts = append(in.ObservedResponsePorts, "tcp/631")
		}
		if obs.Origin == "rtsp" {
			in.ObservedResponsePorts = append(in.ObservedResponsePorts, "tcp/554")
		}
		if ua := str(p, "user_agent"); ua != "" && len(in.UserAgents) < 8 {
			in.UserAgents = append(in.UserAgents, ua)
		}
		if sni := str(p, "sni"); sni != "" {
			if match, ok := deviceSNILibrary.MatchDomain(sni); ok {
				in.SNIEcosystems = append(in.SNIEcosystems, match.Ecosystem)
				if match.BrandEligible && in.SNIBrandHint == "" {
					in.SNIBrandHint = match.Ecosystem
				}
			}
		}
	}
	res := EvaluateCrossVerification(in)
	if res.Status == "" {
		return nil
	}
	return &res
}
