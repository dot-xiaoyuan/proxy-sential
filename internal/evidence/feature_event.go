package evidence

import (
	"strings"

	"proxy-sentinel/internal/normalized"
)

// FeatureEvent retains only fields read by the risk evidence rules. It is a
// derived, short-lived input, never an evidence original or a replacement for
// the authoritative event body. Bump this projection's version when rules
// begin reading another field.
const FeatureEventVersion = "risk-features-v1"

// StreamRiskFeatureEligible is shared by feature persistence and subject
// scheduling. Scoped discovery/shared summaries have their own consumers and
// contain no input retained by the generic risk feature projection.
func StreamRiskFeatureEligible(event normalized.Event) bool {
	if event.Source == "handshake-sidecar" && event.SourceEventType == "handshake" ||
		event.Source == "packet-sidecar" && (event.SourceEventType == "ssdp" || event.SourceEventType == "ieee1905_topology") {
		return false
	}
	ip, _ := event.Subject["ip"].(string)
	return event.Type != "discovery" && strings.TrimSpace(ip) != ""
}

var featureSubjectKeys = []string{"ip", "account_id", "mac", "endpoint_id", "access_id", "entity_role"}
var featureFlowKeys = []string{"dst_port", "dst_ip", "direction", "proto"}
var featurePayloadKeys = []string{
	"user_agent", "ja3", "ja4", "query", "sni", "host", "server_name",
	"application", "software_name", "software_version", "software_type",
	"ttl", "tcp_stack", "origin", "hostname", "device_name", "device_hint",
	"client_fqdn", "vendor_class", "requested_options", "client_mac",
	"os", "os_family", "auth_mac", "observed_mac", "alpn",
	"signature", "signature_id", "category", "severity",
}

func FeatureEvent(event normalized.Event) normalized.Event {
	result := normalized.Event{
		EventID: event.EventID, Timestamp: event.Timestamp, Type: event.Type,
		Source: event.Source, SourceEventType: event.SourceEventType,
		Subject: featureFields(event.Subject, featureSubjectKeys),
		Payload: featureFields(event.Payload, featurePayloadKeys),
		Flow:    featureFields(event.Flow, featureFlowKeys),
	}
	if confidence := declaredVPNRuleConfidence(event.Payload["metadata"]); confidence != "" {
		result.Payload["metadata"] = map[string]any{"proxy_sentinel_confidence": confidence}
	}
	return result
}

func featureFields(fields map[string]any, keys []string) map[string]any {
	result := make(map[string]any, len(keys))
	for _, key := range keys {
		if value, present := fields[key]; present {
			result[key] = value
		}
	}
	return result
}
