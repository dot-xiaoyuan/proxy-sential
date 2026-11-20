package normalized

import "strings"

// IsDiscoveryProjectionEvent identifies events whose facts belong in the
// PostgreSQL discovery state. A mixed source segment can also contain
// diagnostics and other standard events that are archived without a device
// projection receipt.
func IsDiscoveryProjectionEvent(event Event) bool {
	if event.Type == "discovery" {
		return true
	}
	if event.Type != "device" {
		return false
	}
	switch event.SourceEventType {
	case "dhcp", "dhcpv6", "arp", "ndp", "nbns", "llmnr", "lldp", "cdp", "ssdp", "ws_discovery", "snmp", "dns_sd", "mqtt", "coap", "bacnet", "ipp", "onvif", "rtsp", "http", "tls", "ssh", "sip", "ieee1905_client_association", "ieee1905_client_snapshot", "ieee1905_topology":
		return true
	default:
		return false
	}
}

// ProjectsDiscoveryHotPath is the PostgreSQL discovery selection for a live
// source. Packet-sidecar neighbor and TTL chatter stays in the ClickHouse
// body; router clues and IEEE1905 anchors still project. A stream4 key was
// assigned under the previous selection and must still be receipted. Other
// sources keep the full discovery set, including NDP.
func ProjectsDiscoveryHotPath(event Event) bool {
	if event.Source == "packet-sidecar" && !strings.HasPrefix(event.EventID, "stream4-") {
		switch event.SourceEventType {
		case "arp", "ndp", "ttl", "hop_limit":
			return false
		}
	}
	return IsDiscoveryProjectionEvent(event)
}
