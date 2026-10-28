package store

import (
	"strings"

	"proxy-sentinel/internal/fingerprint"
)

// endpointRecognitionEvidence adapts current structured endpoint attributes.
// The original event remains in its owning store; this slice is transient.
func endpointRecognitionEvidence(mac string, attributes map[string]any) []fingerprint.EvidenceSignal {
	signals := endpointRecognitionSignals(mac, attributes)
	out := make([]fingerprint.EvidenceSignal, 0, 24)
	add := func(protocol, field, value, direction string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		out = append(out, fingerprint.EvidenceSignal{Protocol: protocol, Field: field, Value: value, Direction: direction, Association: "direct", SourceFamily: protocol})
	}
	for _, value := range signals.Hostnames {
		add("dhcp", "hostname", value, "device")
	}
	add("dhcp", "dhcp_vendor_class", signals.DHCPVendorClass, "device")
	add("dhcp", "dhcp_requested_options", signals.DHCPRequestedOptions, "device")
	for _, value := range signals.Software {
		add("device", "software_name", value, "device")
	}
	for _, value := range signals.Hints {
		add("device", "device_hint", value, "device")
	}
	for _, value := range signals.UserAgents {
		add("http", "user_agent", value, "client")
	}
	for field, values := range signals.ProtocolFields {
		protocol, direction := recognitionProtocolDirection(field)
		for _, value := range values {
			add(protocol, field, value, direction)
		}
	}
	return out
}

func passiveRecognitionSignals(hints []DiscoveryRecognitionHint) []fingerprint.EvidenceSignal {
	out := make([]fingerprint.EvidenceSignal, 0, len(hints))
	for _, hint := range hints {
		field := hint.Field
		if field == "" {
			if hint.Origin == "dns_sd" || hint.Origin == "dhcp" || hint.Origin == "dhcpv6" {
				field = "hostname"
			} else {
				field = "device_hint"
			}
		}
		protocol, direction := recognitionProtocolDirection(field)
		if hint.Origin != "" {
			protocol = hint.Origin
		}
		association := hint.Association
		if association == "" {
			association = "unique_lease"
		}
		out = append(out, fingerprint.EvidenceSignal{
			Protocol: protocol, Field: field, Value: hint.Value, Direction: direction,
			Association: association, SourceFamily: protocol, EventID: hint.ObservationID,
			ObservedAt: hint.ObservedAt, ValidUntil: hint.ValidUntil,
		})
	}
	return out
}

func recognitionProtocolDirection(field string) (string, string) {
	switch {
	case field == "user_agent" || field == "sip_user_agent" || field == "ja3" || field == "ja4" || field == "tcp_signature":
		return "client", "client"
	case strings.HasPrefix(field, "http_") || field == "favicon_md5":
		return "http", "server"
	case strings.HasPrefix(field, "tls_"):
		return "tls", "server"
	case strings.HasPrefix(field, "ssh_"):
		return "ssh", "server"
	case strings.HasPrefix(field, "sip_"):
		return "sip", "server"
	case strings.HasPrefix(field, "snmp_"):
		return "snmp", "device"
	case strings.HasPrefix(field, "lldp_"):
		return "lldp", "device"
	case strings.HasPrefix(field, "cdp_"):
		return "cdp", "device"
	case strings.HasPrefix(field, "ssdp_"):
		return "ssdp", "device"
	case strings.HasPrefix(field, "dns_sd_") || strings.HasPrefix(field, "mdns_"):
		return "dns_sd", "device"
	case field == "printer_make_and_model":
		return "ipp", "device"
	case strings.HasPrefix(field, "onvif_"):
		return "onvif", "device"
	case strings.HasPrefix(field, "wsd_"):
		return "ws_discovery", "device"
	case strings.HasPrefix(field, "mqtt_"):
		return "mqtt", "device"
	case strings.HasPrefix(field, "coap_"):
		return "coap", "device"
	case strings.HasPrefix(field, "bacnet_"):
		return "bacnet", "device"
	default:
		return "device", "device"
	}
}
