package controlplane

import (
	"fmt"
	"net/netip"
	"strings"
)

// Network boundaries are independent of VLAN, SSID and physical access points.
// Keep empty presets valid, but never persist malformed address ranges.
func normalizeNetworkZoneCIDRs(zone *NetworkZone) error {
	cidrs := make([]string, 0, len(zone.CIDRs))
	seen := make(map[string]bool, len(zone.CIDRs))
	for _, raw := range zone.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("IP 网段格式不正确：%s，请使用 CIDR 格式，例如 222.204.88.0/23", raw)
		}
		cidr := prefix.Masked().String()
		if !seen[cidr] {
			cidrs = append(cidrs, cidr)
			seen[cidr] = true
		}
	}
	zone.CIDRs = cidrs
	return nil
}
