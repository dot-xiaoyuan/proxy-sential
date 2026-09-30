// Package discovery handles scoped asset observations independently of terminal risk identity.
package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"proxy-sentinel/internal/devicename"
	"proxy-sentinel/internal/normalized"
	"regexp"
	"sort"
	"strings"
	"time"
)

const RuleVersion = "discovery-2026.09.21.1"

type Observation struct {
	ID            string           `json:"id"`
	EventID       string           `json:"event_id"`
	SourceID      string           `json:"source_id"`
	SnapshotID    string           `json:"snapshot_id,omitempty"`
	Node          string           `json:"node"`
	Site          string           `json:"site"`
	Domain        string           `json:"domain"`
	VLAN          string           `json:"vlan,omitempty"`
	VRF           string           `json:"vrf,omitempty"`
	IP            string           `json:"ip,omitempty"`
	MAC           string           `json:"mac,omitempty"`
	Name          string           `json:"name,omitempty"`
	OriginalName  string           `json:"original_name,omitempty"`
	NameEncoding  string           `json:"name_encoding,omitempty"`
	Origin        string           `json:"origin"`
	Port          string           `json:"port,omitempty"`
	Interface     string           `json:"interface,omitempty"`
	LocationKind  string           `json:"location_kind,omitempty"`
	DeviceType    string           `json:"device_type,omitempty"`
	Capabilities  []string         `json:"capabilities,omitempty"`
	Confidence    string           `json:"confidence"`
	Explanation   string           `json:"explanation"`
	RuleVersion   string           `json:"rule_version"`
	ConfigVersion int              `json:"config_version"`
	ObservedAt    time.Time        `json:"observed_at"`
	ReportedAt    *time.Time       `json:"reported_at,omitempty"`
	ValidUntil    time.Time        `json:"valid_until"`
	Withdrawn     bool             `json:"withdrawn"`
	Evidence      normalized.Event `json:"evidence"`
}

func (o Observation) Key() string {
	identity := o.MAC
	linkLocalIdentity := false
	if identity == "" && o.Origin == "dns_sd" {
		if target := str(o.Evidence.Payload, "service_target"); target != "" {
			identity = o.SourceID + ":dns:" + strings.ToLower(strings.TrimSuffix(target, "."))
		}
	}
	if identity == "" {
		identity = o.IP
		linkLocalIdentity = strings.HasPrefix(o.IP, "fe80:")
	}
	if identity == "" {
		identity = str(o.Evidence.Payload, "chassis_id")
		if identity == "" {
			identity = str(o.Evidence.Payload, "service_target")
		}
		if identity == "" {
			identity = o.EventID
		}
		identity = o.SourceID + ":" + identity
	}
	if linkLocalIdentity {
		identity += ":" + o.Interface
	}
	if o.Site == "" || o.Domain == "" {
		identity = o.SourceID + ":" + o.Node + ":" + identity
	}
	b, _ := json.Marshal([]string{o.Site, o.Domain, o.VLAN, o.VRF, identity})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16])
}
func (o Observation) Current(now time.Time) bool {
	return !o.Withdrawn && !o.ObservedAt.After(now) && o.ValidUntil.After(now)
}

// NormalizeObservationClassification applies only explicit product or operating
// system evidence. It is also run while reading older observations so a rule
// improvement does not require rewriting the immutable evidence payload.
func NormalizeObservationClassification(o *Observation) {
	if o == nil {
		return
	}
	switch o.Origin {
	case "dhcp":
		identity := strings.ToLower(strings.Join([]string{o.Name, str(o.Evidence.Payload, "hostname"), str(o.Evidence.Payload, "device_hint"), str(o.Evidence.Payload, "vendor_class")}, " "))
		if o.DeviceType == "" && (strings.Contains(identity, "android") || strings.Contains(identity, "vivo-")) {
			o.DeviceType = "mobile"
		}
	case "lldp", "cdp":
		identity := strings.ToLower(strings.Join([]string{o.Name, str(o.Evidence.Payload, "system_name"), str(o.Evidence.Payload, "system_description")}, " "))
		if strings.Contains(identity, "ikuai") {
			o.DeviceType = "router"
			if !containsString(o.Capabilities, "routing") {
				o.Capabilities = append(o.Capabilities, "routing")
			}
		}
	}
}
func str(m map[string]any, k string) string { v, _ := m[k].(string); return strings.TrimSpace(v) }
func number(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}
func FromEvent(e normalized.Event) (Observation, error) {
	o := Observation{EventID: e.EventID, ID: e.EventID, Evidence: e, RuleVersion: RuleVersion, Confidence: "clue"}
	if e.Type != "discovery" || e.EventID == "" {
		return o, errors.New("discovery event required")
	}
	var err error
	o.ObservedAt, err = time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil {
		return o, err
	}
	o.SourceID = str(e.Observer, "source_id")
	o.Node = str(e.Observer, "sensor_id")
	o.SnapshotID = str(e.Observer, "snapshot_id")
	o.ConfigVersion = number(e.Observer, "config_version")
	o.Site = str(e.Subject, "site")
	o.Domain = str(e.Subject, "domain")
	o.VLAN = str(e.Subject, "vlan")
	o.VRF = str(e.Subject, "vrf")
	o.IP = str(e.Subject, "ip")
	o.MAC = str(e.Subject, "mac")
	if o.IP != "" {
		a, err := netip.ParseAddr(o.IP)
		if err != nil || a.IsMulticast() || a.IsUnspecified() || a.IsLoopback() {
			return o, errors.New("invalid device address")
		}
		o.IP = a.Unmap().String()
	}
	if o.MAC != "" {
		m, err := net.ParseMAC(o.MAC)
		if err != nil || len(m) != 6 || m[0]&1 != 0 || m.String() == "00:00:00:00:00:00" {
			return o, errors.New("invalid device MAC")
		}
		o.MAC = m.String()
	}
	o.Origin = str(e.Payload, "origin")
	o.Port = str(e.Payload, "port")
	o.Interface = str(e.Payload, "interface")
	if o.Interface == "" {
		o.Interface = str(e.Observer, "interface")
	}
	o.LocationKind = str(e.Payload, "location_kind")
	o.Name = str(e.Payload, "name")
	NormalizeObservationName(&o)
	label := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(o.Name), "."), ".local")
	if len(o.Name) > 253 || label == "localhost" || label == "unknown" || label == "android" || label == "iphone" || regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^[0-9a-f]{16,}$|^[0-9]+$`).MatchString(label) || strings.ContainsAny(o.Name, "\n\r\x00") {
		o.Name = ""
	}

	ttl := number(e.Payload, "ttl")
	if ttl < 0 || ttl > 604800 {
		return o, errors.New("invalid TTL")
	}
	o.ValidUntil = o.ObservedAt.Add(time.Duration(ttl) * time.Second)
	o.Withdrawn = ttl == 0 || e.Payload["withdrawn"] == true
	switch o.Origin {
	case "fdb", "neighbor", "lldp":
		o.Explanation = "基础设施表项或邻居公告；读取时间不代表终端流量观测时间"
		if o.Origin == "lldp" {
			caps := number(e.Payload, "system_capabilities")
			switch {
			case caps&16 != 0:
				o.DeviceType = "router"
			case caps&8 != 0:
				o.DeviceType = "access_point"
			case caps&4 != 0:
				o.DeviceType = "switch"
			}
			if o.DeviceType != "" {
				o.Explanation = "LLDP 邻居自报能力，属于设备类型线索"
			}
		}
	case "dns_sd":
		if e.Payload["is_response"] != true {
			return o, errors.New("query is not device evidence")
		}
		s := str(e.Payload, "service_type")
		switch s {
		case "_ipp._tcp", "_ipps._tcp", "_printer._tcp":
			o.Capabilities = []string{"printing"}
		case "_uscan._tcp", "_uscans._tcp", "_scanner._tcp":
			o.Capabilities = []string{"scanning"}
		case "_airplay._tcp", "_raop._tcp", "_googlecast._tcp":
			o.Capabilities = []string{"casting"}
		}
		o.Explanation = "服务能力公告，不确认整机类型"
	case "ssdp":
		if e.Payload["is_response"] != true {
			return o, errors.New("SSDP search is not evidence")
		}
		o.Explanation = "SSDP 设备自报信息，不确认整机类型"
		service := strings.ToLower(str(e.Payload, "device_type") + " " + str(e.Payload, "service_type"))
		if strings.Contains(service, "mediarenderer") {
			o.Capabilities = []string{"media_rendering"}
			o.DeviceType = "media_device"
		}
		if strings.Contains(service, "internetgatewaydevice") {
			o.Capabilities = []string{"routing"}
			o.DeviceType = "gateway"
		}
	case "active":
		o.Explanation = "指定目标对只读探测的响应，不代表持续在线"
		switch str(e.Payload, "protocol") {
		case "ipp", "ipps":
			o.Capabilities = []string{"printing"}
		case "onvif":
			o.Capabilities = []string{"network_video"}
			o.DeviceType = "camera"
		}
	default:
		return o, fmt.Errorf("unsupported discovery origin %q", o.Origin)
	}
	return o, nil
}

// NormalizeObservationName cleans the display name without altering the raw
// normalized event retained in Evidence.
func NormalizeObservationName(o *Observation) {
	if o == nil || o.Name == "" {
		return
	}
	original := o.Name
	normalized, encoding := devicename.Normalize(original)
	o.Name = normalized
	if strings.TrimSpace(original) != normalized {
		o.OriginalName = original
		o.NameEncoding = encoding
	}
}

type ScanConfig struct {
	Allow           []string `json:"allow"`
	Exclude         []string `json:"exclude"`
	Addresses       []string `json:"addresses"`
	Interface       string   `json:"interface,omitempty"`
	Protocols       []string `json:"protocols"`
	Sensitive       bool     `json:"sensitive"`
	IntervalSeconds int      `json:"interval_seconds"`
}

func (c ScanConfig) Targets(known []string) ([]string, error) {
	if len(c.Allow) == 0 {
		return nil, errors.New("explicit allowed ranges required")
	}
	var allow, exclude []netip.Prefix
	for i, values := range [][]string{c.Allow, c.Exclude} {
		for _, s := range values {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, err
			}
			p = p.Masked()
			if i == 0 {
				allow = append(allow, p)
			} else {
				exclude = append(exclude, p)
			}
		}
	}
	valid := func(a netip.Addr) bool {
		if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
			return false
		}
		for _, p := range exclude {
			if p.Contains(a) {
				return false
			}
		}
		for _, p := range allow {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	found := map[string]bool{}
	add := func(a netip.Addr) error {
		if !valid(a) {
			return nil
		}
		if a.IsLinkLocalUnicast() && c.Interface == "" {
			return errors.New("link local interface required")
		}
		found[a.String()] = true
		if len(found) > 4096 {
			return errors.New("target limit 4096 exceeded")
		}
		return nil
	}
	for _, p := range allow {
		if !p.Addr().Is4() {
			continue
		}
		if p.Bits() < 20 {
			return nil, errors.New("IPv4 range exceeds 4096 targets")
		}
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			if p.Bits() < 31 && (a == p.Addr() || !p.Contains(a.Next())) {
				continue
			}
			if err := add(a); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range append(append([]string{}, known...), c.Addresses...) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		if err = add(a.Unmap()); err != nil {
			return nil, err
		}
	}
	result := make([]string, 0, len(found))
	for a := range found {
		result = append(result, a)
	}
	sort.Strings(result)
	return result, nil
}
