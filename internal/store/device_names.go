package store

import (
	"fmt"
	"net"
	"proxy-sentinel/internal/normalized"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type DeviceName struct {
	Value         string `json:"value"`
	Source        string `json:"source"`
	Manual        bool   `json:"manual"`
	Status        string `json:"status"`
	MultipleNames bool   `json:"multiple_names"`
}
type DeviceNameEvidence struct {
	ProcessingLatencyMillis *int64    `json:"processing_latency_ms,omitempty"`
	OriginalValue           string    `json:"original_value,omitempty"`
	ParserVersion           string    `json:"parser_version,omitempty"`
	ServiceTarget           string    `json:"service_target,omitempty"`
	EndpointID              string    `json:"endpoint_id,omitempty"`
	Value                   string    `json:"value"`
	Source                  string    `json:"source"`
	Kind                    string    `json:"kind"`
	EventID                 string    `json:"event_id,omitempty"`
	SensorID                string    `json:"sensor_id"`
	CampusID                string    `json:"campus_id,omitempty"`
	Address                 string    `json:"address,omitempty"`
	ObservedAt              time.Time `json:"observed_at"`
	ValidUntil              time.Time `json:"valid_until"`
	Attribution             string    `json:"attribution"`
}

func normalizeDeviceName(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 255 {
		return ""
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return ""
		}
	}
	return value
}

// Reject opaque host labels, not recognizable model-prefixed names such as DESKTOP-1234.
var opaqueDeviceLabel = regexp.MustCompile(`(?i)^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{12,}|([0-9a-f]{2}-){5}[0-9a-f]{2}|[0-9]+)$`)
var serviceNameSuffix = regexp.MustCompile(`(?i)\._[^.]+\._(tcp|udp)\.local$`)

func usableAutomaticDeviceName(value, kind string) bool {
	value = normalizeDeviceName(value)
	if value == "" {
		return false
	}
	if kind == "service" {
		suffix := serviceNameSuffix.FindStringIndex(value)
		if suffix == nil {
			return false
		}
		value = value[:suffix[0]]
	}
	if strings.ContainsAny(value, "/\\") || strings.HasPrefix(value, "_") || strings.Contains(value, "._") || net.ParseIP(value) != nil {
		return false
	}
	if _, err := net.ParseMAC(value); err == nil {
		return false
	}
	label := strings.SplitN(value, ".", 2)[0]
	switch strings.ToLower(label) {
	case "localhost", "localhost6", "localhost6.localdomain6", "unknown", "android", "iphone", "ipad", "ady-al00", "icl-al10", "honor-100":
		return false
	}
	if label == "" || opaqueDeviceLabel.MatchString(label) {
		return false
	}
	return true
}

func extractDeviceNames(e normalized.Event) []DeviceNameEvidence {
	out := []DeviceNameEvidence{}
	at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil || e.Type != "device" || e.EventID == "" {
		return out
	}
	base := DeviceNameEvidence{EventID: e.EventID, SensorID: stringFromMap(e.Observer, "sensor_id"), CampusID: stringFromMap(e.Subject, "campus_id"), Address: stringFromMap(e.Subject, "ip"), ObservedAt: at, ValidUntil: at.Add(7 * 24 * time.Hour), Kind: "hostname", Attribution: "unresolved"}
	add := func(value, source string) {
		original := value
		if value = normalizeDeviceName(value); value != "" && usableAutomaticDeviceName(value, base.Kind) {
			n := base
			n.Value = value
			n.OriginalValue = original
			n.ParserVersion = stringFromMap(e.Payload, "parser_version")
			n.Source = source
			out = append(out, n)
		}
	}
	switch stringFromMap(e.Payload, "origin") {
	case "dhcp":
		if mac, err := net.ParseMAC(stringFromMap(e.Subject, "mac")); err == nil && len(mac) == 6 && mac[0]&1 == 0 && mac.String() != "00:00:00:00:00:00" {
			base.EndpointID = "mac:" + mac.String()
			base.Attribution = "dhcp_mac"
		}
		add(stringFromMap(e.Payload, "client_fqdn"), "dhcp_fqdn")
		add(stringFromMap(e.Payload, "hostname"), "dhcp_hostname")
	case "mdns":
		if fmt.Sprint(e.Payload["is_response"]) != "true" {
			return out
		}
		typ := strings.ToUpper(stringFromMap(e.Payload, "record_type"))
		if typ == "SRV" {
			ttl, err := strconv.ParseUint(fmt.Sprint(e.Payload["record_ttl"]), 10, 32)
			target := normalizeDeviceName(stringFromMap(e.Payload, "service_target"))
			if err != nil || target == "" {
				return out
			}
			if ttl > 7*24*3600 {
				ttl = 7 * 24 * 3600
			}
			base.Kind = "service"
			base.Address = ""
			base.ServiceTarget = target
			base.ValidUntil = at.Add(time.Duration(ttl) * time.Second)
			add(stringFromMap(e.Payload, "record_name"), "mdns_service")
			return out
		}
		address := net.ParseIP(stringFromMap(e.Payload, "record_address"))
		if address == nil || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			return out
		}
		if (typ != "A" && typ != "AAAA") || (typ == "A" && address.To4() == nil) || (typ == "AAAA" && address.To4() != nil) {
			return out
		}
		ttl, err := strconv.ParseUint(fmt.Sprint(e.Payload["record_ttl"]), 10, 32)
		if err != nil {
			return out
		}
		if ttl > 7*24*3600 {
			ttl = 7 * 24 * 3600
		}
		base.Address = address.String()
		base.ValidUntil = at.Add(time.Duration(ttl) * time.Second)
		add(stringFromMap(e.Payload, "record_name"), "mdns_hostname")
	}
	return out
}
func namePriority(source string) int {
	switch source {
	case "dhcp_fqdn":
		return 3
	case "dhcp_hostname":
		return 2
	case "mdns_hostname":
		return 1
	}
	return 0
}
func selectDeviceName(input []DeviceNameEvidence, manual string, now time.Time) *DeviceName {
	// Collapse each record stream before expiry selection: a goodbye supersedes
	// an older announcement even when the older TTL has not elapsed.
	latest := map[string]DeviceNameEvidence{}
	for _, n := range input {
		if n.Kind != "hostname" && n.Kind != "" || n.ObservedAt.After(now) || !usableAutomaticDeviceName(n.Value, "hostname") {
			continue
		}
		key := n.Source + "\x00" + strings.ToLower(n.Value) + "\x00" + n.SensorID + "\x00" + n.Address
		old, ok := latest[key]
		if !ok || n.ObservedAt.After(old.ObservedAt) || (n.ObservedAt.Equal(old.ObservedAt) && n.EventID > old.EventID) {
			latest[key] = n
		}
	}
	names := []DeviceNameEvidence{}
	distinct := map[string]bool{}
	for _, n := range latest {
		names = append(names, n)
		distinct[strings.ToLower(n.Value)] = true
	}
	if manual != "" {
		return &DeviceName{Value: manual, Source: "manual", Manual: true, Status: "current", MultipleNames: len(distinct) > 1}
	}
	if len(names) == 0 {
		return nil
	}
	current := func(n DeviceNameEvidence) bool {
		return n.ValidUntil.After(now) && n.ObservedAt.Add(7*24*time.Hour).After(now) && n.Attribution != "legacy_attribute"
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := names[i], names[j]
		if current(a) != current(b) {
			return current(a)
		}
		if namePriority(a.Source) != namePriority(b.Source) {
			return namePriority(a.Source) > namePriority(b.Source)
		}
		if !a.ObservedAt.Equal(b.ObservedAt) {
			return a.ObservedAt.After(b.ObservedAt)
		}
		return a.EventID > b.EventID
	})
	n := names[0]
	status := "historical"
	if current(n) {
		status = "current"
	}
	value := n.Value
	if n.Source == "mdns_hostname" && strings.HasSuffix(strings.ToLower(value), ".local") {
		value = value[:len(value)-len(".local")]
	}
	return &DeviceName{Value: value, Source: n.Source, Status: status, MultipleNames: len(distinct) > 1}
}
