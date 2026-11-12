package census

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

// Identifier counts a network address observed at a controlled mirror scope.
// It is deliberately not a physical-device identity.
type Identifier struct {
	ScopeKey     string    `json:"scope_key"`
	SensorID     string    `json:"sensor_id"`
	CampusID     string    `json:"campus_id"`
	AccessDomain string    `json:"access_domain"`
	VLAN         string    `json:"vlan"`
	VRF          string    `json:"vrf"`
	Kind         string    `json:"kind"`
	Value        string    `json:"value"`
	IPFamily     int       `json:"ip_family"`
	RandomMAC    bool      `json:"random_mac"`
	ObservedAt   time.Time `json:"observed_at"`
	EventID      string    `json:"event_id"`
	Source       string    `json:"source"`
}

type Binding struct {
	ScopeKey   string    `json:"scope_key"`
	IP         string    `json:"ip"`
	MAC        string    `json:"mac"`
	ObservedAt time.Time `json:"observed_at"`
	ValidUntil time.Time `json:"valid_until"`
	Withdrawn  bool      `json:"withdrawn"`
	EventID    string    `json:"event_id"`
	Source     string    `json:"source"`
}

func field(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// Numeric packet-sidecar tags and JSON numbers use the same decimal scope as
// discovery's passiveString. Invalid tags never collapse into missing VLAN.
func identifierVLAN(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	var text string
	switch v := value.(type) {
	case string:
		text = strings.TrimSpace(v)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		text = fmt.Sprint(v)
	default:
		return "", false
	}
	if text == "" {
		return "", true
	}
	tag, err := strconv.ParseUint(text, 10, 12)
	if err != nil || tag > 4094 || strconv.FormatUint(tag, 10) != text {
		return "", false
	}
	return text, true
}

func canonicalIP(value string, allow []netip.Prefix) (string, int) {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
		return "", 0
	}
	ip = ip.Unmap()
	for _, prefix := range allow {
		if prefix.Contains(ip) {
			if ip.Is4() {
				if prefix.Addr().Is4() && prefix.Bits() <= 30 {
					base := binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())
					address := binary.BigEndian.Uint32(ip.AsSlice())
					broadcast := base | ((uint32(1) << uint(32-prefix.Bits())) - 1)
					if address == base || address == broadcast {
						return "", 0
					}
				}
				return ip.String(), 4
			}
			return ip.String(), 6
		}
	}
	return "", 0
}

func canonicalMAC(value string) (string, bool) {
	mac, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return "", false
	}
	return strings.ToLower(mac.String()), mac[0]&2 != 0
}

func scopeKey(sensor, campus, domain, vlan, vrf string) string {
	raw, _ := json.Marshal([]string{sensor, campus, domain, vlan, vrf})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

// ScopeKey uses the same dimensions as the discovery identity projection.
func ScopeKey(sensor, campus, domain, vlan, vrf string) string {
	return scopeKey(sensor, campus, domain, vlan, vrf)
}

func ScopeVersion(prefixes []netip.Prefix) string {
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		values = append(values, prefix.Masked().String())
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, ",")))
	return hex.EncodeToString(sum[:8])
}

func trustedMAC(event normalized.Event, kind, mac string) bool {
	if mac == "" {
		return false
	}
	if frame := field(event.Payload, "ethernet_source_mac"); frame != "" {
		canonical, _ := canonicalMAC(frame)
		if canonical != mac {
			return false
		}
	}
	switch kind {
	case "arp", "ndp", "dhcp":
		return true
	case "mdns", "dns_sd", "ssdp", "ws_discovery":
		if subject, subjectErr := netip.ParseAddr(field(event.Subject, "ip")); subjectErr == nil {
			if source, sourceErr := netip.ParseAddr(field(event.Flow, "src_ip")); sourceErr != nil || subject.Unmap() != source.Unmap() {
				return false
			}
		}
		if event.Source == "packet-sidecar" && (kind == "ssdp" || kind == "ws_discovery") {
			return true // devicesignal.baseControlSignal uses the Ethernet frame source.
		}
		if event.Payload["l2_source_mac_direct"] != true {
			return false
		}
		responder, _ := canonicalMAC(field(event.Payload, "responder_l2_mac"))
		return responder == mac
	default:
		return false
	}
}

func leaseSeconds(payload map[string]any) int {
	for _, name := range []string{"lease_time", "ttl"} {
		if value, err := strconv.Atoi(field(payload, name)); err == nil && value > 0 {
			return min(value, 7*24*3600)
		}
		if value, ok := payload[name].(float64); ok && value > 0 {
			return min(int(value), 7*24*3600)
		}
	}
	return 24 * 3600
}

func dhcpAction(payload map[string]any) string {
	action := strings.ToLower(first(field(payload, "message_type"), field(payload, "action"), field(payload, "msg_types")))
	for _, part := range strings.Split(action, ",") {
		switch strings.TrimSpace(part) {
		case "ack", "reply", "release", "stop", "nak":
			action = strings.TrimSpace(part)
		}
	}
	return action
}

// Identify adapts one standard event without altering its evidence or identity.
// The caller supplies the site's explicit CIDRs; an empty scope admits nothing.
func Identify(event normalized.Event, allow []netip.Prefix) ([]Identifier, []Binding) {
	// A configured collector binding that failed validation cannot establish
	// any scoped identifier. Keep the original failure on the source event.
	if field(event.Observer, "capture_scope_issue") != "" {
		return nil, nil
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil || event.EventID == "" || len(allow) == 0 {
		return nil, nil
	}
	sensor := field(event.Observer, "sensor_id")
	if sensor == "" {
		return nil, nil
	}
	campus := first(field(event.Subject, "campus_id"), field(event.Subject, "site"))
	domain := first(field(event.Payload, "access_domain"), field(event.Subject, "domain"), field(event.Observer, "interface"))
	payloadVLAN, payloadVLANValid := identifierVLAN(event.Payload["vlan"])
	subjectVLAN, subjectVLANValid := identifierVLAN(event.Subject["vlan"])
	if !payloadVLANValid || !subjectVLANValid || payloadVLAN != "" && subjectVLAN != "" && payloadVLAN != subjectVLAN {
		return nil, nil
	}
	vlan := first(payloadVLAN, subjectVLAN)
	vrf := first(field(event.Payload, "vrf"), field(event.Subject, "vrf"))
	scope := scopeKey(sensor, campus, domain, vlan, vrf)
	kind := strings.ToLower(event.SourceEventType)
	base := Identifier{ScopeKey: scope, SensorID: sensor, CampusID: campus, AccessDomain: domain, VLAN: vlan, VRF: vrf, ObservedAt: at.UTC(), EventID: event.EventID, Source: first(event.Source, kind)}
	seen := map[string]bool{}
	identifiers := make([]Identifier, 0, 4)
	appendIP := func(value string) {
		ip, family := canonicalIP(value, allow)
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		item := base
		item.Kind, item.Value, item.IPFamily = "ip", ip, family
		identifiers = append(identifiers, item)
	}
	// A DHCP request can advertise an address it does not yet own. A release
	// keeps its prior address claim visible in the observation window while
	// ending the effective binding.
	action := dhcpAction(event.Payload)
	dhcpRequest := kind == "dhcp" && action != "ack" && action != "reply" && action != "release" && action != "stop" && action != "nak"
	if !dhcpRequest {
		appendIP(field(event.Subject, "ip"))
	}
	appendIP(field(event.Flow, "src_ip"))
	appendIP(field(event.Flow, "dst_ip"))
	mac, random := canonicalMAC(field(event.Subject, "mac"))
	if !trustedMAC(event, kind, mac) || kind == "dhcp" && event.Payload["discovery_scope_conflict"] == true {
		return identifiers, nil
	}
	macItem := base
	macItem.Kind, macItem.Value, macItem.RandomMAC = "mac", mac, random
	identifiers = append(identifiers, macItem)
	ip, _ := canonicalIP(field(event.Subject, "ip"), allow)
	if ip == "" || kind != "arp" && kind != "ndp" && kind != "dhcp" {
		return identifiers, nil
	}
	if kind == "dhcp" && dhcpRequest {
		return identifiers, nil
	}
	seconds := 600
	if kind == "dhcp" {
		seconds = leaseSeconds(event.Payload)
	}
	withdrawn := event.Payload["withdrawn"] == true || kind == "dhcp" && (action == "release" || action == "stop" || action == "nak")
	until := at.UTC().Add(time.Duration(seconds) * time.Second)
	if withdrawn {
		until = at.UTC()
	}
	return identifiers, []Binding{{ScopeKey: scope, IP: ip, MAC: mac, ObservedAt: at.UTC(), ValidUntil: until, Withdrawn: withdrawn, EventID: event.EventID, Source: kind + ":" + base.Source}}
}
