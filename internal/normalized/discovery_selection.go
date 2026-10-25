package normalized

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
	case "dhcp", "dhcpv6", "arp", "ndp", "nbns", "llmnr", "lldp", "cdp", "ssdp", "ws_discovery", "snmp", "dns_sd", "mqtt", "coap", "bacnet", "ipp", "rtsp", "http", "tls", "ieee1905_client_association":
		return true
	default:
		return false
	}
}
