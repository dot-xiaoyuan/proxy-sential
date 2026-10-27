package fingerprint

import (
	"sort"
	"strings"
	"time"
)

// EvidenceSignal is a bounded, attributed standard-event field. EventID points
// to the single authoritative event; the recognition result stores no raw copy.
type EvidenceSignal struct {
	Protocol     string    `json:"protocol"`
	Field        string    `json:"field"`
	Value        string    `json:"-"`
	Direction    string    `json:"direction"`
	Association  string    `json:"association"`
	SourceFamily string    `json:"source_family"`
	EventID      string    `json:"event_id"`
	ObservedAt   time.Time `json:"observed_at"`
	ValidUntil   time.Time `json:"valid_until"`
}

type EvidenceRef struct {
	EventID      string `json:"event_id"`
	Protocol     string `json:"protocol"`
	Field        string `json:"field"`
	SourceFamily string `json:"source_family"`
	ObservedAt   string `json:"observed_at,omitempty"`
}

type Diagnostics struct {
	Stage           string   `json:"stage"`
	Reason          string   `json:"reason,omitempty"`
	Protocols       []string `json:"protocols,omitempty"`
	AcceptedSignals int      `json:"accepted_signals"`
	CandidateRules  int      `json:"candidate_rules"`
}

// A client fingerprint can describe a software stack, never the server or a
// physical endpoint. Server banners and certificates require server ownership.
var physicalEvidenceFields = map[string]string{
	"hostname": "device", "dhcp_vendor_class": "device", "dhcp_requested_options": "device",
	"device_hint": "device", "model_hint": "device", "os_hint": "device", "software_name": "device",
	"ssdp_model": "device", "ssdp_manufacturer": "device", "dns_sd_model": "device", "mdns_model": "device",
	"snmp_model": "device", "snmp_sysoid": "device", "snmp_sysdescr": "device",
	"lldp_system_name": "device", "lldp_system_description": "device", "lldp_capabilities": "device",
	"cdp_device_id": "device", "cdp_platform": "device", "service_type": "device",
	"printer_make_and_model": "device", "onvif_model": "device", "onvif_manufacturer": "device",
	"mqtt_model": "device", "coap_device_type": "device", "bacnet_model": "device",
	"http_server": "server", "http_title": "server", "http_www_authenticate": "server", "http_body": "server", "favicon_md5": "server",
	"tls_subject": "server", "tls_issuer": "server", "tls_san": "server", "ssh_banner": "server", "sip_server": "server",
}

var clientEvidenceFields = map[string]bool{"user_agent": true, "ja3": true, "ja4": true, "tcp_signature": true, "sip_user_agent": true}

// IdentifyEvidence turns protocol-specific observations into the existing
// recognition engine's field inputs. It never guesses ownership from an IP.
func (l *Library) IdentifyEvidence(mac string, evidence []EvidenceSignal, now time.Time) Result {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	signals := Signals{MAC: mac, ProtocolFields: map[string][]string{}}
	refs := make([]EvidenceRef, 0, min(len(evidence), 16))
	protocols := map[string]bool{}
	seen := map[string]bool{}
	valid, ambiguous, accepted := false, false, false
	acceptedSignals := 0
	for _, item := range evidence {
		if !item.ObservedAt.IsZero() && item.ObservedAt.After(now) || !item.ValidUntil.IsZero() && !item.ValidUntil.After(now) {
			continue
		}
		valid = true
		if item.Association != "direct" && item.Association != "mac" && item.Association != "unique_lease" {
			ambiguous = true
			continue
		}
		field := strings.TrimSpace(item.Field)
		value := strings.TrimSpace(item.Value)
		maxValueBytes := 512
		if field == "http_body" {
			maxValueBytes = 16384
		}
		if value == "" || len(value) > maxValueBytes {
			continue
		}
		want, physical := physicalEvidenceFields[field]
		if !physical && !clientEvidenceFields[field] || physical && item.Direction != want {
			continue
		}
		if !physical && item.Direction != "client" {
			continue
		}
		if !evidenceProtocolAllowsField(item.Protocol, field) {
			continue
		}
		key := item.EventID + "\x00" + field + "\x00" + value
		if seen[key] {
			continue
		}
		seen[key] = true
		accepted = true
		acceptedSignals++
		protocols[item.Protocol] = true
		switch field {
		case "hostname":
			signals.Hostnames = append(signals.Hostnames, value)
		case "dhcp_vendor_class":
			if signals.DHCPVendorClass == "" {
				signals.DHCPVendorClass = value
			}
		case "dhcp_requested_options":
			if signals.DHCPRequestedOptions == "" {
				signals.DHCPRequestedOptions = value
			}
		case "user_agent":
			signals.UserAgents = append(signals.UserAgents, value)
		case "device_hint", "model_hint", "os_hint":
			signals.Hints = append(signals.Hints, value)
		case "software_name":
			signals.Software = append(signals.Software, value)
		default:
			signals.ProtocolFields[field] = append(signals.ProtocolFields[field], value)
		}
		if physical && item.EventID != "" && len(refs) < 16 {
			ref := EvidenceRef{EventID: item.EventID, Protocol: item.Protocol, Field: field, SourceFamily: item.SourceFamily}
			if !item.ObservedAt.IsZero() {
				ref.ObservedAt = item.ObservedAt.UTC().Format(time.RFC3339Nano)
			}
			refs = append(refs, ref)
		}
	}
	result := l.IdentifySignals(signals)
	result.Diagnostics.AcceptedSignals = acceptedSignals
	result.EvidenceRefs = refs
	result.Diagnostics.Protocols = make([]string, 0, len(protocols))
	for protocol := range protocols {
		result.Diagnostics.Protocols = append(result.Diagnostics.Protocols, protocol)
	}
	sort.Strings(result.Diagnostics.Protocols)
	result.Diagnostics.Stage = recognitionStage(result)
	switch {
	case result.Conflict:
		result.Diagnostics.Reason = "conflict"
	case result.Brand != "" || result.Model != "" || result.DeviceType != "" || result.OSFamily != "":
	case ambiguous && !accepted:
		result.Diagnostics.Reason = "unattributed"
	case !valid:
		result.Diagnostics.Reason = "no_current_signal"
	default:
		result.Diagnostics.Reason = "insufficient_specificity"
	}
	return result
}

// Protocol validation prevents a correctly directed but mislabelled field from
// acquiring the authority of another protocol. Direct endpoint attributes use
// "device" only for the small set of legacy, already-attributed hints.
func evidenceProtocolAllowsField(protocol, field string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch protocol {
	case "device":
		return field == "device_hint" || field == "model_hint" || field == "os_hint" || field == "software_name" || field == "service_type"
	case "dhcp", "dhcpv6":
		return field == "hostname" || field == "dhcp_vendor_class" || field == "dhcp_requested_options" || field == "device_hint"
	case "lldp":
		return strings.HasPrefix(field, "lldp_")
	case "cdp":
		return strings.HasPrefix(field, "cdp_")
	case "dns_sd", "mdns":
		return field == "hostname" || field == "dns_sd_model" || field == "mdns_model" || field == "service_type"
	case "ssdp":
		return strings.HasPrefix(field, "ssdp_") || field == "service_type"
	case "snmp":
		return strings.HasPrefix(field, "snmp_")
	case "ipp":
		return field == "printer_make_and_model" || field == "service_type"
	case "onvif":
		return strings.HasPrefix(field, "onvif_") || field == "service_type"
	case "mqtt":
		return field == "mqtt_model" || field == "service_type"
	case "coap":
		return field == "coap_device_type" || field == "service_type"
	case "bacnet":
		return field == "bacnet_model" || field == "service_type"
	case "http":
		return strings.HasPrefix(field, "http_") || field == "favicon_md5" || field == "user_agent"
	case "tls":
		return strings.HasPrefix(field, "tls_") || field == "ja3" || field == "ja4"
	case "ssh":
		return field == "ssh_banner"
	case "sip":
		return field == "sip_server" || field == "sip_user_agent"
	case "client":
		return clientEvidenceFields[field]
	}
	return false
}

func recognitionStage(result Result) string {
	switch {
	case result.Model != "":
		return "model"
	case result.DeviceType != "":
		return "device_type"
	case result.Brand != "":
		return "brand"
	case result.Vendor != "":
		return "vendor"
	case result.OSFamily != "":
		return "os_family"
	default:
		return "none"
	}
}
