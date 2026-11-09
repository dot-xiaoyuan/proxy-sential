package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestSSDPIKuaiServerClassifiesGatewayAsRouter(t *testing.T) {
	now := time.Now().UTC()
	o := Observation{
		ID: "ssdp", Origin: "ssdp", IP: "192.168.0.1", MAC: "00:e0:67:2a:4f:4c",
		ObservedAt: now, ValidUntil: now.Add(time.Hour), Confidence: "strong",
		Evidence: normalized.Event{Payload: map[string]any{
			"server":   "iKuaiOS/iKuaiOS UPnP/1.1 MiniUPnPd/1.9",
			"location": "http://192.168.0.1:1900/rootDesc.xml",
			"st":       "uuid:3d3cec3a-8cf0-11e0-98ee-001a6bd2d07b",
		}},
	}
	NormalizeObservationClassification(&o)
	if o.DeviceType != "router" {
		t.Fatalf("device type = %q, want router", o.DeviceType)
	}
	if !containsString(o.Capabilities, "routing") {
		t.Fatalf("routing capability missing: %v", o.Capabilities)
	}

	plain := Observation{Origin: "ssdp", ObservedAt: now, ValidUntil: now.Add(time.Hour), Evidence: normalized.Event{Payload: map[string]any{"server": "Linux UPnP/1.0"}}}
	NormalizeObservationClassification(&plain)
	if plain.DeviceType != "" {
		t.Fatalf("unexpected classification for generic SSDP server: %q", plain.DeviceType)
	}
}
