package normalized

import "strings"

// Portable DHCP clients describe network software, not a host OS. Keep their
// raw fields in the event, but exclude them from OS inference. Older adapters
// emitted a Linux hint solely from these client names; exclude that hint too.
func DeviceProfileHintText(fields map[string]any) string {
	portable := false
	for _, key := range []string{"vendor_class", "software_name", "software_version"} {
		value, _ := fields[key].(string)
		portable = portable || IsPortableDHCPClient(value)
	}
	parts := []string{}
	for _, key := range []string{"device_hint", "hostname", "client_fqdn", "device_name", "query", "vendor_class", "software_name", "software_version", "software_type", "os", "os_family"} {
		value, _ := fields[key].(string)
		value = strings.TrimSpace(strings.ToLower(value))
		if portable && key == "device_hint" && value == "linux" {
			continue
		}
		if (key == "vendor_class" || key == "software_name" || key == "software_version") && IsPortableDHCPClient(value) {
			continue
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, " ")
}

func IsPortableDHCPClient(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	for _, name := range []string{"dhcpcd", "udhcpc", "udhcp", "dhclient"} {
		if value == name {
			return true
		}
		if strings.HasPrefix(value, name) && len(value) > len(name) && strings.ContainsRune("-/ :", rune(value[len(name)])) {
			return true
		}
	}
	return false
}
