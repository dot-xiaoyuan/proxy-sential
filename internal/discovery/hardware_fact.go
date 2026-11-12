package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

// HardwareProjectionEnabled includes shadow writes but never enables v2 reads.
func HardwareProjectionEnabled() bool {
	return os.Getenv("PROXY_SENTINEL_HARDWARE_V2") == "true" || os.Getenv("PROXY_SENTINEL_HARDWARE_SHADOW") == "true"
}

// StoredHardwareSignal persists only bounded extracted fields. EvidenceSignal's
// Value is intentionally json:"-", so it must not be used as a persistence DTO.
type StoredHardwareSignal struct {
	Protocol string `json:"protocol"`
	Field    string `json:"field"`
	Value    string `json:"value"`
}

type HardwareFact struct {
	IdentityKey  string                 `json:"identity_key"`
	FactKey      string                 `json:"fact_key"`
	ClaimKey     string                 `json:"claim_key"`
	SensorID     string                 `json:"sensor_id"`
	CampusID     string                 `json:"campus_id"`
	AccessDomain string                 `json:"access_domain"`
	VLAN         string                 `json:"vlan"`
	VRF          string                 `json:"vrf"`
	MAC          string                 `json:"mac"`
	DeviceKey    string                 `json:"device_key"`
	Source       string                 `json:"source"`
	FirstSeen    time.Time              `json:"first_seen"`
	ObservedAt   time.Time              `json:"observed_at"`
	ActiveUntil  time.Time              `json:"active_until"`
	Revoked      bool                   `json:"revoked"`
	EvidenceID   string                 `json:"evidence_id"`
	RawRef       map[string]any         `json:"raw_ref,omitempty"`
	Signals      []StoredHardwareSignal `json:"signals"`
	AddressOnly  bool                   `json:"address_only"`
}

func HardwareFactNewer(incoming, existing HardwareFact) bool {
	return incoming.ObservedAt.After(existing.ObservedAt) || incoming.ObservedAt.Equal(existing.ObservedAt) && incoming.Revoked && !existing.Revoked
}

func HardwareIdentityKey(sensor, site, domain, vlan, vrf, mac string) string {
	// PostgreSQL jsonb renders UTF-8 literally (including U+2028/U+2029) and
	// does not HTML-escape scope labels. Encoding that exact JSON form avoids
	// different identity strings for the same scope in the SQL and Go readers.
	var out strings.Builder
	out.WriteByte('[')
	for i, value := range []string{"identity", sensor, site, domain, vlan, vrf, "mac", strings.ToLower(mac)} {
		if i > 0 {
			out.WriteString(", ")
		}
		out.WriteByte('"')
		for _, r := range value {
			switch r {
			case '"':
				out.WriteString(`\"`)
			case '\\':
				out.WriteString(`\\`)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 0x20 {
					fmt.Fprintf(&out, `\u%04x`, r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	}
	out.WriteByte(']')
	return out.String()
}

func hardwareHash(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func hardwareDirectOwnership(o Observation) bool {
	p := o.Evidence.Payload
	for _, key := range []string{"vlan", "vrf"} {
		a, b := str(p, key), str(o.Evidence.Subject, key)
		if a != "" && b != "" && a != b {
			return false
		}
	}
	if p["endpoint_identity_unverified"] == true {
		return false
	}
	if str(p, "hardware_identity") == "unique_binding" {
		return true
	}
	switch o.Origin {
	case "arp", "ndp", "dhcp":
		return true
	case "sadp":
		return p["is_response"] == true && (str(p, "identity_status") == "direct_l2" || str(p, "identity_status") == "arp_binding") && strings.EqualFold(str(p, "claimed_mac"), o.MAC) && str(p, "claimed_ip") == o.IP
	case "dns_sd":
		return p["l2_source_mac_direct"] == true && strings.EqualFold(str(p, "responder_l2_mac"), o.MAC)
	}
	return false
}

// HardwareFactFromObservation never promotes legacy classifications: it adapts
// the attributed original product fields and lets the unified catalog decide.
func HardwareFactFromObservation(o Observation) (*HardwareFact, error) {
	// Explicit scope failures must not become trusted hardware through a
	// legacy display-site fallback. The source event remains unchanged.
	if str(o.Evidence.Observer, "capture_scope_issue") != "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(o.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" || o.Node == "" || o.Site == "" || o.Domain == "" || o.ObservedAt.IsZero() || !hardwareDirectOwnership(o) {
		return nil, nil
	}
	p := o.Evidence.Payload
	switch o.Origin {
	case "snmp", "bacnet", "modbus", "ssdp", "ws_discovery", "ipp", "onvif", "rtsp", "http_device":
		if p["is_response"] != true {
			return nil, nil
		}
	}
	f := &HardwareFact{SensorID: o.Node, CampusID: o.Site, AccessDomain: o.Domain, VLAN: o.VLAN, VRF: o.VRF, MAC: strings.ToLower(mac.String()), DeviceKey: o.Key(), Source: o.Origin, FirstSeen: o.ObservedAt, ObservedAt: o.ObservedAt, ActiveUntil: o.ValidUntil, Revoked: o.Withdrawn, EvidenceID: firstText(o.EventID, o.ID), RawRef: o.Evidence.RawRef, Signals: []StoredHardwareSignal{}, AddressOnly: o.Origin == "arp" || o.Origin == "ndp"}
	f.IdentityKey = HardwareIdentityKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF, f.MAC)
	f.ClaimKey = hardwareHash([]string{o.SourceID, o.Origin, str(p, "service_instance"), str(p, "usn"), str(p, "bacnet_device_id"), str(p, "modbus_unit_id")})
	fields := map[string]string{}
	switch o.Origin {
	case "sadp":
		fields["sadp_model"] = str(p, "product_model")
	case "dns_sd":
		fields["dns_sd_model"] = firstText(o.ModelName, str(p, "product_model"))
		fields["service_type"] = str(p, "service_type")
	case "ssdp":
		fields["ssdp_model"] = firstText(o.ModelName, str(p, "product_model"))
		fields["ssdp_manufacturer"] = o.Manufacturer
	case "snmp":
		fields["snmp_sysdescr"] = str(p, "system_description")
		fields["snmp_sysoid"] = str(p, "system_object_id")
		fields["snmp_model"] = str(p, "product_model")
		if values, ok := p["snmp_varbinds"]; ok {
			raw, e := json.Marshal(values)
			if e != nil {
				return nil, e
			}
			var bounded map[string]string
			if json.Unmarshal(raw, &bounded) != nil || len(bounded) > normalized.HardwareMaxVarbinds {
				return nil, fmt.Errorf("invalid bounded SNMP varbinds")
			}
			for k, v := range bounded {
				if len(k) > 256 || len(v) > normalized.HardwareMaxValueBytes {
					return nil, fmt.Errorf("SNMP value exceeds hardware bound")
				}
			}
			fields["snmp_oid_values"] = string(raw)
		}
	case "bacnet":
		fields["bacnet_model"] = str(p, "product_model")
	case "modbus":
		fields["modbus_model"] = str(p, "product_model")
	case "lldp":
		fields["lldp_system_description"] = str(p, "system_description")
	case "cdp":
		fields["cdp_platform"] = str(p, "platform")
	case "ipp":
		fields["printer_make_and_model"] = firstText(str(p, "printer_make_and_model"), o.ModelName)
	case "onvif":
		fields["onvif_model"] = o.ModelName
	case "ws_discovery":
		fields["wsd_model"] = o.ModelName
	case "http_device":
		fields["http_server"] = str(p, "server")
		fields["http_title"] = str(p, "title")
	case "sip":
		fields["sip_server"] = str(p, "server")
	case "tls_device":
		fields["tls_subject"] = str(p, "certificate_subject")
		fields["tls_issuer"] = str(p, "certificate_issuer")
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := strings.TrimSpace(fields[key])
		if value == "" {
			continue
		}
		bound := normalized.HardwareMaxValueBytes
		if key == "snmp_oid_values" {
			bound = 48 * 1024
		}
		if len(value) > bound {
			return nil, fmt.Errorf("hardware field %s exceeds bound", key)
		}
		f.Signals = append(f.Signals, StoredHardwareSignal{Protocol: o.Origin, Field: key, Value: value})
	}
	// Different product contents coexist; a newer model cannot silently erase a
	// contradictory older direct self-report. Withdrawals target the claim below.
	f.FactKey = hardwareHash([]any{f.ClaimKey, f.Signals})
	if len(f.Signals) == 0 {
		f.FactKey = hardwareHash([]string{f.ClaimKey, "activity"})
	}
	return f, nil
}

func (f HardwareFact) Evidence() []fingerprint.EvidenceSignal {
	out := make([]fingerprint.EvidenceSignal, 0, len(f.Signals))
	if f.Revoked {
		return out
	}
	for _, s := range f.Signals {
		protocol, direction := s.Protocol, "device"
		switch protocol {
		case "http_device":
			protocol = "http"
		case "tls_device":
			protocol = "tls"
		}
		switch s.Field {
		case "http_server", "http_title", "sip_server", "tls_subject", "tls_issuer":
			direction = "server"
		}
		out = append(out, fingerprint.EvidenceSignal{Protocol: protocol, Field: s.Field, Value: s.Value, Direction: direction, Association: "direct", SourceFamily: s.Protocol, EventID: f.EvidenceID, ObservedAt: f.ObservedAt})
	}
	return out
}
