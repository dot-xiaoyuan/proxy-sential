package discovery

import (
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"strings"
)

// AdaptDiscoveryEvent preserves the immutable source event in the task. Only
// the observation adapter receives these normalized discovery-specific fields.
func AdaptDiscoveryEvent(event normalized.Event) (normalized.Event, error) {
	if containsNUL(event.Payload) || containsNUL(event.Subject) || containsNUL(event.Observer) {
		return event, fmt.Errorf("protocol text contains NUL; original evidence retained")
	}
	if event.Type == "discovery" && str(event.Payload, "origin") != "" {
		return event, nil
	}
	raw, _ := json.Marshal(event)
	var e normalized.Event
	_ = json.Unmarshal(raw, &e)
	if e.Payload == nil {
		e.Payload = map[string]any{}
	}
	if e.Observer == nil {
		e.Observer = map[string]any{}
	}
	if e.Subject == nil {
		e.Subject = map[string]any{}
	}
	kind := e.SourceEventType
	switch kind {
	case "dhcp", "dhcpv6", "arp", "ndp", "nbns", "llmnr", "lldp", "cdp", "ssdp", "ws_discovery", "snmp", "dns_sd", "mqtt", "coap", "bacnet", "ipp", "rtsp", "http", "tls":
	default:
		return e, fmt.Errorf("not a discovery protocol")
	}
	e.Type = "discovery"
	e.Payload["origin"] = kind
	e.Observer["source_id"] = firstText(str(e.Observer, "source_id"), e.Source+":"+str(e.Observer, "sensor_id"))
	e.Subject["site"] = firstText(str(e.Subject, "site"), str(e.Subject, "campus_id"))
	e.Subject["domain"] = firstText(str(e.Subject, "domain"), firstText(str(e.Payload, "access_domain"), str(e.Observer, "interface")))
	if _, ok := e.Payload["ttl"]; !ok {
		e.Payload["ttl"] = 600
	}
	if kind == "dhcp" || kind == "dhcpv6" {
		if e.Payload["discovery_scope_conflict"] == true {
			return e, fmt.Errorf("DHCP aggregate crosses capture scopes")
		}
		action := strings.ToLower(firstText(str(e.Payload, "message_type"), firstText(str(e.Payload, "action"), str(e.Payload, "msg_types"))))
		for _, part := range strings.Split(action, ",") {
			part = strings.TrimSpace(part)
			if part == "ack" || part == "reply" || part == "release" || part == "nak" {
				action = part
			}
		}
		if action != "ack" && action != "reply" && action != "release" && action != "stop" && action != "nak" {
			return e, fmt.Errorf("DHCP request is not an address binding")
		}
		if action == "release" || action == "stop" || action == "nak" {
			e.Payload["ttl"] = 0
			e.Payload["withdrawn"] = true
		} else {
			if v, ok := e.Payload["lease_time"]; ok {
				e.Payload["ttl"] = v
			}
		}
		e.Payload["address_binding"] = !boolPayload(e.Payload, "withdrawn")
		e.Payload["name"] = firstText(str(e.Payload, "hostname"), str(e.Payload, "device_name"))
	}
	return e, nil
}

func boolPayload(p map[string]any, key string) bool { v, _ := p[key].(bool); return v }
