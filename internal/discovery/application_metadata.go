package discovery

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// ParseMQTTDiscovery reads only explicit Home Assistant discovery documents.
// Telemetry, client IDs, passwords, arbitrary topics and retained device state
// never become hardware classification evidence.
func ParseMQTTDiscovery(topic string, body []byte, fromClient bool) (map[string]any, error) {
	if !fromClient || len(body) > 16384 || len(body) == 0 {
		return nil, fmt.Errorf("MQTT client discovery document required")
	}
	parts := strings.Split(topic, "/")
	if len(parts) < 3 || parts[0] != "homeassistant" || parts[len(parts)-1] != "config" {
		return nil, fmt.Errorf("not an MQTT discovery document")
	}
	var doc struct {
		Device struct {
			Manufacturer string `json:"manufacturer"`
			Model        string `json:"model"`
			Name         string `json:"name"`
			Identifiers  any    `json:"identifiers"`
		} `json:"device"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	p := map[string]any{"origin": "mqtt", "is_response": true, "ttl": 3600, "service_instance": topic, "manufacturer": cleanDescriptionText(doc.Device.Manufacturer), "product_model": cleanDescriptionText(doc.Device.Model), "name": cleanDescriptionText(doc.Device.Name)}
	if doc.Device.Model != "" && doc.Device.Manufacturer != "" {
		switch parts[1] {
		case "sensor", "binary_sensor":
			p["product_type"] = "sensor"
			p["device_declaration"] = true
		}
	}
	// Publishers may be gateways announcing another device. Keep declared IDs
	// as relations; only a current address binding can attribute them to sender.
	var identifiers []string
	switch v := doc.Device.Identifiers.(type) {
	case string:
		identifiers = []string{v}
	case []any:
		for _, x := range v {
			if value, ok := x.(string); ok {
				identifiers = append(identifiers, value)
			}
		}
	}
	if len(identifiers) > 16 {
		return nil, fmt.Errorf("MQTT device identifier budget")
	}
	for _, id := range identifiers {
		if mac, e := net.ParseMAC(id); e == nil {
			p["declared_mac"] = mac.String()
			break
		}
	}
	return p, nil
}
