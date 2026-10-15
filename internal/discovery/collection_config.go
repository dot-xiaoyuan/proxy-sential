package discovery

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"proxy-sentinel/internal/normalized"
	"strings"
	"time"
)

type ProtocolOwner struct {
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	Enabled  bool   `json:"enabled"`
}
type EventBinding struct {
	Source    string    `json:"source"`
	Protocol  string    `json:"protocol"`
	Sensor    string    `json:"sensor_id"`
	Site      string    `json:"site"`
	Domain    string    `json:"domain"`
	Interface string    `json:"interface"`
	ValidFrom time.Time `json:"valid_from"`
}
type CollectionConfig struct {
	EventBindings   []EventBinding   `json:"event_bindings"`
	EnrichmentPaths []EnrichmentPath `json:"enrichment_paths"`
	Version         int              `json:"version"`
	AllowedCIDRs    string           `json:"allowed_cidrs"`
	Protocols       []ProtocolOwner  `json:"protocols"`
}

func DefaultCollectionConfig() CollectionConfig {
	c := CollectionConfig{Version: 1, AllowedCIDRs: PrivateDiscoveryCIDRs}
	for _, p := range DiscoveryCaptureProtocols {
		c.Protocols = append(c.Protocols, ProtocolOwner{p, "discovery-worker", true})
	}
	c.Protocols = append(c.Protocols, ProtocolOwner{"dhcp", "zeek", true})
	for _, p := range []string{"ipp", "rtsp", "http", "tls", "mqtt"} {
		c.Protocols = append(c.Protocols, ProtocolOwner{p, "zeek", false})
	}
	return c
}
func LoadCollectionConfig(path string) (CollectionConfig, error) {
	if path == "" {
		return DefaultCollectionConfig(), nil
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return CollectionConfig{}, e
	}
	if len(b) > 65536 {
		return CollectionConfig{}, fmt.Errorf("collection configuration budget")
	}
	var c CollectionConfig
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.Version != 1 {
		return c, fmt.Errorf("unsupported collection configuration")
	}
	if _, e = ParseCaptureCIDRs(c.AllowedCIDRs); e != nil {
		return c, e
	}
	known := map[string]string{}
	for _, p := range DefaultCollectionConfig().Protocols {
		known[p.Protocol] = p.Source
	}
	seen := map[string]bool{}
	for _, p := range c.Protocols {
		if seen[p.Protocol] || known[p.Protocol] != p.Source {
			return c, fmt.Errorf("ambiguous protocol owner: %s", p.Protocol)
		}
		seen[p.Protocol] = true
	}
	for _, b := range c.EventBindings {
		if b.Source != "zeek" || b.Protocol != "dhcp" || b.Sensor == "" || b.Site == "" || b.Domain == "" || b.Interface == "" || b.ValidFrom.IsZero() {
			return c, fmt.Errorf("invalid controlled event binding")
		}
	}
	return c, nil
}
func (c CollectionConfig) CaptureProtocols() []string {
	p := []string{}
	for _, r := range c.Protocols {
		if r.Enabled && r.Source == "discovery-worker" {
			p = append(p, r.Protocol)
		}
	}
	return p
}
func (c CollectionConfig) Enabled(protocol string) bool {
	for _, p := range c.Protocols {
		if p.Protocol == protocol {
			return p.Enabled
		}
	}
	return false
}

// The generic file ingester only owns Zeek protocols. Discovery-worker events
// already have their own durable spool and must not be re-imported from the
// legacy device-signals stream merely because their protocol is enabled.
func (c CollectionConfig) IngestOwns(event normalized.Event) bool {
	for _, p := range c.Protocols {
		if p.Protocol == event.SourceEventType {
			return p.Enabled && p.Source == "zeek" && event.Source == "zeek"
		}
	}
	return false
}

func (c CollectionConfig) AllowsAddress(ip string) bool {
	if ip == "" {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !IsPrivateDiscoveryAddress(ip) {
		return false
	}
	for _, cidr := range strings.Split(c.AllowedCIDRs, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err == nil && prefix.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// Input remains in the original ingest batch even when it is outside the
// discovery scope. Only eligible device evidence gets projection work.
func (c CollectionConfig) SelectEvents(events []normalized.Event) []normalized.Event {
	selected := []normalized.Event{}
	for _, event := range events {
		if !c.IngestOwns(event) {
			continue
		}
		adapted, err := BindDiscoveryEvent(event, c)
		if err != nil || !c.AllowsAddress(str(adapted.Subject, "ip")) {
			continue
		}
		if _, err = FromEvent(adapted); err != nil {
			continue
		}
		selected = append(selected, adapted)
	}
	return selected
}

func BindDiscoveryEvent(event normalized.Event, c CollectionConfig) (normalized.Event, error) {
	adapted, e := AdaptDiscoveryEvent(event)
	if e != nil {
		return event, e
	}
	for _, b := range c.EventBindings {
		if event.Source != b.Source || event.SourceEventType != b.Protocol || str(event.Observer, "sensor_id") != b.Sensor {
			continue
		}
		at, e := time.Parse(time.RFC3339Nano, event.Timestamp)
		if e != nil || at.Before(b.ValidFrom) {
			return event, fmt.Errorf("discovery event predates controlled scope binding")
		}
		if site := str(adapted.Subject, "site"); site != "" && site != b.Site {
			return event, fmt.Errorf("discovery site binding conflict")
		}
		if domain := str(adapted.Subject, "domain"); domain != "" && domain != b.Domain {
			return event, fmt.Errorf("discovery domain binding conflict")
		}
		adapted.Subject["site"] = b.Site
		adapted.Subject["domain"] = b.Domain
		adapted.Observer["interface"] = b.Interface
		adapted.Observer["discovery_scope_version"] = c.Version
		if adapted.RawRef == nil {
			adapted.RawRef = map[string]any{}
		}
		adapted.RawRef["source_event_hash"] = contentHash(event)
	}
	return adapted, nil
}
