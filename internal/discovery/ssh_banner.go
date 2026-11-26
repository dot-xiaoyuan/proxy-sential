package discovery

import "strings"

// SSHBannerIdentity 从 SSH 服务端 Banner（如 SSH-2.0-Comware-7.1.070）提取可追溯的设备/系统线索。
// 仅输出明确带厂商或系统特征的 Banner，泛用 OpenSSH 不强行猜测整机品类。
func SSHBannerIdentity(banner string) (deviceType, brand, osHint string) {
	b := strings.TrimSpace(banner)
	if !strings.HasPrefix(strings.ToUpper(b), "SSH-") {
		return "", "", ""
	}
	lower := strings.ToLower(b)
	switch {
	case strings.Contains(lower, "comware"):
		return "switch", "H3C", "Comware"
	case strings.Contains(lower, "ruijie"):
		return "switch", "Ruijie", "RGOS"
	case strings.Contains(lower, "huawei") || strings.Contains(lower, "-vrp"):
		return "switch", "Huawei", "VRP"
	case strings.Contains(lower, "cisco-"):
		return "router", "Cisco", "IOS"
	case strings.Contains(lower, "rosssh"):
		return "router", "MikroTik", "RouterOS"
	case strings.Contains(lower, "dropbear"):
		return "", "", "Embedded Linux"
	case strings.Contains(lower, "openssh") && strings.Contains(lower, "windows"):
		return "", "", "Windows"
	case strings.Contains(lower, "openssh") && (strings.Contains(lower, "ubuntu") || strings.Contains(lower, "debian") || strings.Contains(lower, "el7") || strings.Contains(lower, "el8") || strings.Contains(lower, "el9") || strings.Contains(lower, "openeuler")):
		return "", "", "Linux"
	case strings.Contains(lower, "openssh") && strings.Contains(lower, "freebsd"):
		return "", "", "FreeBSD"
	}
	return "", "", ""
}
