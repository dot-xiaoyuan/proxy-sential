package discovery

import (
	"errors"
	"net/netip"
	"strings"

	"proxy-sentinel/internal/normalized"
)

func isMDNSHostAnnouncement(event normalized.Event) bool {
	return str(event.Payload, "origin") == "dns_sd" && str(event.Payload, "dns_record_kind") == "host_address"
}

func canonicalDNSOwner(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func validateMDNSHostAnnouncement(event normalized.Event) error {
	name := str(event.Payload, "dns_name")
	if canonicalDNSOwner(name) == "" || len(name) > 254 || strings.ContainsAny(name, "\x00\r\n") {
		return errors.New("mDNS host announcement requires a bounded DNS owner")
	}
	ip, err := netip.ParseAddr(str(event.Subject, "ip"))
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return errors.New("mDNS host announcement requires a unicast advertised address")
	}
	if kind := str(event.Payload, "dns_record_type"); kind != "A" && kind != "AAAA" || (kind == "A") != ip.Is4() {
		return errors.New("mDNS host record type and address disagree")
	}
	source, err := netip.ParseAddr(str(event.Payload, "announcer_ip"))
	if err != nil || source.IsUnspecified() || source.IsMulticast() || source.IsLoopback() {
		return errors.New("mDNS host announcement requires a unicast announcer")
	}
	if str(event.Subject, "mac") != "" || event.Payload["address_binding"] == true {
		return errors.New("mDNS host announcement cannot bind a terminal MAC or address")
	}
	for _, field := range []string{"service_type", "service_port", "service_instance", "service_target"} {
		if _, exists := event.Payload[field]; exists {
			return errors.New("mDNS host announcement cannot declare a service")
		}
	}
	return nil
}

// Evidence-specific transport details remain in the authoritative event, but
// do not turn an unchanged host/name fact into new semantic content.
func discoveryPayloadFieldIsEvidenceOnly(event normalized.Event, field string) bool {
	if str(event.Payload, "origin") != "dns_sd" {
		return false
	}
	switch field {
	case "dns_message_sha256", "dns_message_id", "dns_record_ttl", "dns_message_coverage":
		return true
	}
	return false
}

// A real SRV identity is available only when the event carries its target and
// port. Generic service hints retain their existing identity semantics.
func hasDNSSDServiceRecord(event normalized.Event) bool {
	_, hasPort := event.Payload["service_port"]
	return str(event.Payload, "origin") == "dns_sd" && str(event.Payload, "service_target") != "" && hasPort
}
