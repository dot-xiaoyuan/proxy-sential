package evidence

import (
	"net/netip"
	"strings"

	"proxy-sentinel/internal/normalized"
)

// Host TTL paths use IPv4 unicast traffic. Multicast/broadcast and mDNS may
// deliberately use protocol-specific hop limits, not the host's default TTL.
// Raw events remain available; IPv6 requires its own validated rule.
func hostIPv4TTL(event normalized.Event) bool {
	if scope := stringValue(event.Flow, "traffic_scope"); scope != "" && scope != "unicast" {
		return false
	}
	ip, err := netip.ParseAddr(subjectString(event, "ip"))
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() == "255.255.255.255" {
		return false
	}
	for _, fields := range []map[string]any{event.Flow, event.Payload} {
		if version, ok := numberValue(fields["ip_version"]); ok && version == 6 {
			return false
		}
	}
	if dst, err := netip.ParseAddr(stringValue(event.Flow, "dst_ip")); err == nil {
		if !dst.Is4() || dst.IsMulticast() || dst.IsUnspecified() || dst.String() == "255.255.255.255" {
			return false
		}
	}
	if strings.EqualFold(stringValue(event.Flow, "proto"), "udp") {
		for _, key := range []string{"src_port", "dst_port"} {
			if port, ok := numberValue(event.Flow[key]); ok && port == 5353 {
				return false
			}
		}
	}
	return true
}
