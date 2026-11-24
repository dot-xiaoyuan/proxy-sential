package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
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
	if str(o.Evidence.Observer, "capture_scope_issue") != "" {
		return false
	}
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
	if str(p, "hardware_identity") == "unique_binding" && o.MAC != "" {
		return true
	}
	switch o.Origin {
	case "arp", "ndp", "dhcp":
		return true
	case "dhcp_client":
		message := strings.ToUpper(str(p, "msg_types"))
		clientAddress := strings.EqualFold(str(p, "client_chaddr"), o.MAC) ||
			str(p, "client_id_hwtype") == "1" && strings.EqualFold(str(p, "client_id_hwaddr"), o.MAC)
		return o.IP == "" && p["request_only"] == true && p["discovery_scope_conflict"] != true &&
			str(p, "dhcp_log_kind") == "dhcp-message" && (message == "REQUEST" || message == "DISCOVER" || message == "INFORM") &&
			strings.EqualFold(str(o.Evidence.Subject, "mac"), o.MAC) && clientAddress
	case "sadp":
		return p["is_response"] == true && (str(p, "identity_status") == "direct_l2" || str(p, "identity_status") == "arp_binding") && strings.EqualFold(str(p, "claimed_mac"), o.MAC) && str(p, "claimed_ip") == o.IP
	case "dns_sd":
		return p["l2_source_mac_direct"] == true && strings.EqualFold(str(p, "responder_l2_mac"), o.MAC)
	}
	return false
}

// MarkUnattributedSNMPClue keeps saved product evidence available when the
// response cannot establish a hardware identity in its capture scope.
func (o *Observation) MarkUnattributedSNMPClue() {
	if o.Origin != "snmp" {
		return
	}
	p := o.Evidence.Payload
	if p["is_response"] == true && o.IP != "" && str(p, "response_source_ip") == o.IP &&
		o.Node != "" && o.Site != "" && o.Domain != "" && canonicalEndpointMAC("mac:"+strings.ToLower(o.MAC)) != "" &&
		hardwareDirectOwnership(*o) {
		return
	}
	o.Confidence = "clue"
	o.DeviceType = ""
	o.Explanation = "SNMP 产品信息，设备归属待核实"
}

var dhcpProductClass = regexp.MustCompile(`(?i)^(?:H3C\. H3C (WA[0-9][A-Z0-9-]{1,30})|HUAWEI:router:((?:AX|WS)[0-9][A-Z0-9-]{1,30}):[0-9A-Z.:_-]{1,40})$`)

func dhcpACKProfile(o Observation) (product, candidateType string) {
	p := o.Evidence.Payload
	if o.Withdrawn || !o.ValidUntil.After(o.ObservedAt) || o.IP == "" ||
		o.IP != str(p, "assigned_addr") || p["discovery_scope_conflict"] == true || p["request_only"] == true {
		return "", ""
	}
	if vlan := str(p, "dhcp_capture_vlan"); vlan != "" && vlan != o.VLAN {
		return "", ""
	}
	actions := strings.FieldsFunc(strings.ToUpper(str(p, "msg_types")), func(r rune) bool { return r == ',' || r == ' ' })
	if !slices.Contains(actions, "ACK") || slices.Contains(actions, "NAK") || slices.Contains(actions, "RELEASE") {
		return "", ""
	}
	match := dhcpProductClass.FindStringSubmatch(strings.TrimSpace(str(p, "vendor_class")))
	if match != nil {
		return strings.ToUpper(firstText(match[1], match[2])), ""
	}
	// These two fields come from the client side of the same acknowledged
	// exchange. The catalog only accepts complete manufacturer-listed codes.
	if !slices.Contains(actions, "REQUEST") || !hasOriginalFileRecord(o.Evidence.RawRef) ||
		o.Evidence.Source != "zeek" || o.VLAN == "" || str(p, "dhcp_capture_vlan") != o.VLAN ||
		!strings.EqualFold(str(p, "mac"), o.MAC) {
		return "", ""
	}
	option60 := str(p, "dhcp_product_vendor_class")
	if option60 == "" && p["dhcp_option60_present"] == true {
		option60 = str(p, "vendor_class")
	}
	host := str(p, "hostname")
	if code := dhcpInfrastructureCode(option60, host, o.MAC); code != "" {
		return code, ""
	}
	vendor := strings.Split(option60, ":")
	if len(vendor) == 3 && vendor[0] == "HUAWEI" && (vendor[1] == "openharmony" || vendor[1] == "android") &&
		vendor[2] == host {
		if kind := dhcpReportedType(vendor[2]); kind != "" {
			return vendor[2], kind
		}
	}
	return "", ""
}

// The prefixes below are the registered vendor prefixes verified in the V8
// IEEE table. Products with device-specific hostnames must also match the
// original client MAC, including the suffix advertised by that product.
func dhcpInfrastructureCode(option60, host, mac string) string {
	mac = strings.ToLower(mac)
	switch option60 {
	case "CloudSwitch_1":
		if len(mac) == 17 && strings.HasPrefix(mac, "74:3a:20:") && host == "S24G-U_"+strings.ToUpper(strings.ReplaceAll(mac[12:], ":", "")) {
			return "S24G-U"
		}
	case "huawei AP":
		if strings.HasPrefix(mac, "28:41:ec:") && host == "Huawei AP-AirEngine5762-10-"+mac {
			return "AirEngine 5762-10"
		}
	case "YLS220-24G2F":
		if strings.HasPrefix(mac, "78:60:5b:") && host == option60 {
			return option60
		}
	case "TL-SG2008D":
		if strings.HasPrefix(mac, "9c:47:82:") {
			return option60
		}
	case "H3C NX30":
		if strings.HasPrefix(mac, "70:c6:dd:") && host == "H3C_NX30" {
			return "NX30"
		}
	}
	return ""
}

// DHCPLeaseCandidateType returns a model-derived type clue for an attributed
// lease. The hardware projection keeps the self-report out of confirming rules.
func DHCPLeaseCandidateType(o Observation) string {
	if o.Origin != "dhcp" || o.Node == "" || o.Site == "" || o.Domain == "" || o.MAC == "" || !hardwareDirectOwnership(o) {
		return ""
	}
	_, kind := dhcpACKProfile(o)
	return kind
}

// HardwareFactFromObservation never promotes legacy classifications: it adapts
// the attributed original product fields and lets the unified catalog decide.
func HardwareFactFromObservation(o Observation) (*HardwareFact, error) {
	// Older SIP adapters hashed an empty record. Such an ID cannot identify
	// the source evidence; only a replay of the verified original may fix it.
	if o.Origin == "sip" && o.EventID == "zeek-e3b0c44298fc1c149afbf4c8" {
		return nil, nil
	}
	mac, err := net.ParseMAC(o.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" || o.Node == "" || o.Site == "" || o.Domain == "" || o.ObservedAt.IsZero() || !hardwareDirectOwnership(o) {
		return nil, nil
	}
	p := o.Evidence.Payload
	switch o.Origin {
	case "rtsp":
		if IPProductAttribution(o) != "request_ip" {
			return nil, nil
		}
	case "ssdp", "ws_discovery":
		if p["is_response"] != true && p["is_announcement"] != true {
			return nil, nil
		}
	case "snmp", "bacnet", "modbus", "ipp", "onvif", "http_device":
		if p["is_response"] != true {
			return nil, nil
		}
	}
	f := &HardwareFact{SensorID: o.Node, CampusID: o.Site, AccessDomain: o.Domain, VLAN: o.VLAN, VRF: o.VRF, MAC: strings.ToLower(mac.String()), DeviceKey: o.Key(), Source: o.Origin, FirstSeen: o.ObservedAt, ObservedAt: o.ObservedAt, ActiveUntil: o.ValidUntil, Revoked: o.Withdrawn, EvidenceID: firstText(o.EventID, o.ID), RawRef: o.Evidence.RawRef, Signals: []StoredHardwareSignal{}, AddressOnly: o.Origin == "arp" || o.Origin == "ndp"}
	f.IdentityKey = HardwareIdentityKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF, f.MAC)
	f.ClaimKey = hardwareHash([]string{o.SourceID, o.Origin, str(p, "service_instance"), str(p, "usn"), str(p, "bacnet_device_id"), str(p, "modbus_unit_id")})
	f.Signals, err = hardwareObservationSignals(o)
	if err != nil {
		return nil, err
	}
	// Different product contents coexist; a newer model cannot silently erase a
	// contradictory older direct self-report. Withdrawals target the claim below.
	f.FactKey = hardwareHash([]any{f.ClaimKey, f.Signals})
	if len(f.Signals) == 0 {
		f.FactKey = hardwareHash([]string{f.ClaimKey, "activity"})
	}
	return f, nil
}

// hardwareObservationSignals extracts bounded product fields without asserting a physical identity.
func hardwareObservationSignals(o Observation) ([]StoredHardwareSignal, error) {
	p := o.Evidence.Payload
	fields := map[string]string{}
	switch o.Origin {
	case "dhcp":
		code, candidate := dhcpACKProfile(o)
		if candidate != "" {
			fields["dhcp_reported_model"] = code
		} else {
			fields["dhcp_product_model"] = code
		}
	case "dhcp_client":
		if hardwareDirectOwnership(o) {
			for _, key := range []string{"vendor_class", "requested_options", "hostname", "dhcp_options", "client_id_hwtype", "client_id_hwaddr", "client_chaddr"} {
				fields["dhcp_"+key] = str(p, key)
			}
		}
	case "sadp":
		fields["sadp_model"] = str(p, "product_model")
	case "dns_sd":
		fields["dns_sd_model"] = firstText(o.ModelName, str(p, "product_model"))
		fields["dns_sd_receiver_implementation"] = dnsSDReceiverImplementation(o)
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
	case "rtsp":
		if IPProductAttribution(o) == "request_ip" {
			fields["rtsp_user_agent"] = str(p, "user_agent")
		}
	case "sip":
		if o.IP == str(o.Evidence.Flow, "src_ip") && (str(p, "attribution_side") == "client" || str(o.Evidence.Flow, "direction") == "client") {
			fields["sip_user_agent"] = str(p, "user_agent")
		}
		if o.IP == str(o.Evidence.Flow, "dst_ip") && (str(p, "attribution_side") == "server" || str(o.Evidence.Flow, "direction") == "server") {
			fields["sip_server"] = str(p, "server")
		}
	case "tls_device":
		fields["tls_subject"] = str(p, "certificate_subject")
		fields["tls_issuer"] = str(p, "certificate_issuer")
		fields["tls_san"] = str(p, "certificate_san")
	}
	signals := []StoredHardwareSignal{}
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
		signals = append(signals, StoredHardwareSignal{Protocol: o.Origin, Field: key, Value: value})
	}
	return signals, nil
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
		case "sip_user_agent", "rtsp_user_agent":
			direction = "client"
		case "http_server", "http_title", "sip_server", "tls_subject", "tls_issuer", "tls_san":
			direction = "server"
		}
		var validUntil time.Time
		if s.Field == "dns_sd_receiver_implementation" {
			validUntil = f.ActiveUntil
		}
		out = append(out, fingerprint.EvidenceSignal{Protocol: protocol, Field: s.Field, Value: s.Value, Direction: direction, Association: "direct", SourceFamily: s.Protocol, EventID: f.EvidenceID, ObservedAt: f.ObservedAt, ValidUntil: validUntil})
	}
	return out
}

func (f HardwareFact) hasReferencedProductRecord() bool {
	if f.Revoked {
		return false
	}
	if f.Source == "sadp" {
		return validOriginalDigest(str(f.RawRef, "payload_sha256"))
	}
	if f.Source != "dns_sd" {
		return false
	}
	if hasOriginalFileRecord(f.RawRef) {
		return true
	}
	if str(f.RawRef, "backend") != "derived_dns_sd" {
		return false
	}
	// The SRV join emits exactly [SRV, address, TXT]. Older persisted joins
	// predate the explicit TXT tag. Two-element PTR/address pairs have no TXT.
	var records []struct {
		Event string         `json:"event_id"`
		Kind  string         `json:"record_type"`
		Ref   map[string]any `json:"raw_ref"`
	}
	raw, err := json.Marshal(f.RawRef["records"])
	if err != nil || json.Unmarshal(raw, &records) != nil || len(records) != 3 {
		return false
	}
	txt := records[2]
	if (txt.Kind != "" && txt.Kind != "TXT") || !hasOriginalFileRecord(txt.Ref) {
		return false
	}
	return txt.Event == "zeek-"+str(txt.Ref, "content_sha256")[:24]
}

func hasOriginalFileRecord(ref map[string]any) bool {
	if !validOriginalDigest(str(ref, "content_sha256")) {
		return false
	}
	batch, _ := ref["ingest_source_ref"].(map[string]any)
	return str(batch, "file_id") != "" || str(ref, "original_file_id") != ""
}

func validOriginalDigest(digest string) bool {
	if len(digest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}
