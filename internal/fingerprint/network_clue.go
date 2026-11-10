package fingerprint

import "strings"

// A network role inferred only from a self-reported hostname is a clue, not a
// confirmed type. Keep it below the UI's confirmed-type threshold until an
// independent protocol (UPnP/IGD, HTTP server, LLDP/CDP, SNMP, mDNS model or a
// non-hostname rule) agrees.
const hostnameNetworkClueConfidence = .65

var networkDeviceRoles = map[string]bool{
	"router":       true,
	"access_point": true,
	"switch":       true,
	"firewall":     true,
}

// applyNetworkDeviceAmbiguityPolicy prevents two common misreadings:
//  1. a hostname such as a router model being presented as a confirmed router;
//  2. a DHCP/client user-agent OS fingerprint becoming the operating system of
//     a router, AP or switch, even though those devices do not run that OS.
func applyNetworkDeviceAmbiguityPolicy(result *Result, signals Signals) {
	if result == nil || !networkDeviceRoles[strings.ToLower(strings.TrimSpace(result.DeviceType))] {
		return
	}
	if !hasIndependentNetworkType(result, signals) {
		cap := hostnameNetworkClueConfidence
		if result.Confidence > cap {
			result.Confidence = cap
		}
		if result.DeviceTypeConfidence > cap {
			result.DeviceTypeConfidence = cap
		}
		if result.ModelConfidence > cap {
			result.ModelConfidence = cap
		}
		brandCorroborated := vendorMatchesBrand(result.Vendor, result.Brand)
		if !brandCorroborated && result.BrandConfidence > cap {
			result.BrandConfidence = cap
		}
		capHostnameDimensions(result, cap, brandCorroborated)
		if hasHostnameNetworkTypeEvidence(result) {
			result.Evidence = append(result.Evidence, "主机名线索: 网络设备类型缺少独立协议确认，按类型线索展示")
		} else {
			result.Evidence = append(result.Evidence, "网络设备类型缺少独立协议确认，按类型线索展示")
		}
	}
	suppressWeakNetworkOS(result)
}

// hasIndependentNetworkType looks for device-type evidence for the same role
// that did not come from a hostname. An OUI alone is deliberately excluded.
func hasIndependentNetworkType(result *Result, signals Signals) bool {
	for _, entry := range result.DimensionEvidence {
		if entry.Dimension != "device_type" || !strings.EqualFold(strings.TrimSpace(entry.Value), result.DeviceType) {
			continue
		}
		if entry.Field == "hostname" || entry.Layer == "hostname_hint" {
			continue
		}
		return true
	}
	return hasIndependentNetworkSignal(signals, result.Model)
}

func hasIndependentNetworkSignal(signals Signals, model string) bool {
	fields := []string{
		"ssdp_model", "ssdp_manufacturer", "http_server", "http_title",
		"snmp_sysdescr", "snmp_sysoid", "lldp_system_description",
		"lldp_capabilities", "cdp_platform", "cdp_device_id",
		"dns_sd_model", "mdns_model", "service_type",
	}
	markers := []string{
		"router", "gateway", "access point", "wireless ap", "switch",
		"tp-link", "cisco", "h3c", "ruijie", "huawei", "internetgatewaydevice",
	}
	model = strings.ToLower(strings.TrimSpace(model))
	vendorClass := strings.ToLower(strings.TrimSpace(signals.DHCPVendorClass))
	vendorMarkers := []string{"router", "gateway", "access point", "wireless ap", "switch", "tp-link", "cisco", "h3c", "ruijie", "huawei ap"}
	for _, marker := range vendorMarkers {
		if strings.Contains(vendorClass, marker) {
			return true
		}
	}
	for _, field := range fields {
		for _, value := range signals.ProtocolFields[field] {
			lower := strings.ToLower(strings.TrimSpace(value))
			if lower == "" {
				continue
			}
			if model != "" && strings.Contains(lower, model) {
				return true
			}
			for _, marker := range markers {
				if strings.Contains(lower, marker) {
					return true
				}
			}
		}
	}
	return false
}

func hasHostnameNetworkTypeEvidence(result *Result) bool {
	for _, entry := range result.DimensionEvidence {
		if entry.Dimension != "device_type" || !strings.EqualFold(strings.TrimSpace(entry.Value), result.DeviceType) {
			continue
		}
		if entry.Field == "hostname" || entry.Layer == "hostname_hint" {
			return true
		}
	}
	return false
}

func capHostnameDimensions(result *Result, cap float64, brandCorroborated bool) {
	for index := range result.DimensionEvidence {
		entry := &result.DimensionEvidence[index]
		if entry.Field != "hostname" {
			continue
		}
		if entry.Layer != "device_rule" && entry.Layer != "hostname_hint" && entry.Layer != "protocol_catalog" {
			continue
		}
		switch entry.Dimension {
		case "brand":
			if brandCorroborated {
				continue
			}
		case "device_type", "model", "product_family":
		default:
			continue
		}
		if entry.Confidence > cap {
			entry.Confidence = cap
		}
	}
}

func vendorMatchesBrand(vendor, brand string) bool {
	v := strings.ToLower(strings.TrimSpace(vendor))
	b := strings.ToLower(strings.TrimSpace(brand))
	if v == "" || b == "" {
		return false
	}
	return strings.Contains(v, b) || strings.Contains(b, v)
}

func suppressWeakNetworkOS(result *Result) {
	if strings.TrimSpace(result.OSFamily) == "" {
		return
	}
	if hasStrongNetworkOSEvidence(result) {
		return
	}
	ignored := result.OSFamily
	result.OSFamily = ""
	result.OSFamilyConfidence = 0
	filtered := result.DimensionEvidence[:0]
	for _, entry := range result.DimensionEvidence {
		if entry.Dimension == "os_family" {
			continue
		}
		filtered = append(filtered, entry)
	}
	result.DimensionEvidence = filtered
	result.Evidence = append(result.Evidence, "网络设备不采用 DHCP/UA/TTL 指纹确认操作系统；已忽略 "+ignored)
}

func hasStrongNetworkOSEvidence(result *Result) bool {
	for _, entry := range result.DimensionEvidence {
		if entry.Dimension != "os_family" {
			continue
		}
		switch entry.Layer {
		case "protocol_catalog", "model_catalog", "snmp":
			return true
		case "device_rule":
			if entry.Field != "hostname" {
				return true
			}
		}
	}
	return false
}
