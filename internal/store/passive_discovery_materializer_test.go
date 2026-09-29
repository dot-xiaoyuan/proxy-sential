package store

import (
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestPassiveDiscoveryUsesBoundedSignalStream(t *testing.T) {
	source, err := os.ReadFile("passive_discovery_materializer.go")
	if err != nil {
		t.Fatal(err)
	}
	querySource := string(source)
	if !strings.Contains(querySource, "FROM passive_discovery_events_v1 PREWHERE") || strings.Contains(querySource, "FROM normalized_events PREWHERE") {
		t.Fatal("passive materializer must not scan the general normalized event table")
	}
}

func passiveTestEvent(kind, ip, mac string, payload map[string]any) normalized.Event {
	return normalized.Event{
		EventID:         kind + "-event",
		SourceEventType: kind,
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		Observer:        map[string]any{"sensor_id": "office-30", "interface": "ens1f1"},
		Subject:         map[string]any{"ip": ip, "mac": mac, "campus_id": "office-30"},
		Payload:         payload,
	}
}

func TestPassiveDiscoveryScopeExcludesPublicAndSpecialAddresses(t *testing.T) {
	scope, err := parsePassiveDiscoveryScope("192.168.0.0/24,240e:35a:431:a901::/64")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.168.0.254", "240e:35a:431:a901::22", "fe80::1"} {
		if !scope.allows(address) {
			t.Fatalf("expected %s in discovery scope", address)
		}
	}
	for _, address := range []string{"218.30.19.40", "8.8.8.8", "224.0.0.251", "::", "ff02::1"} {
		if scope.allows(address) {
			t.Fatalf("unexpected discovery scope match for %s", address)
		}
	}
}

func TestPassiveDiscoveryRequiresDHCPACK(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	ack := passiveTestEvent("dhcp", "192.168.0.63", "00:11:22:33:44:55", map[string]any{"msg_types": "REQUEST,ACK", "lease_time": 3600, "hostname": "tp-link"})
	observation, reason := passiveObservation(ack, scope)
	if reason != "" || observation.Origin != "dhcp" || observation.Confidence != "confirmed" {
		t.Fatalf("ACK was not materialized: reason=%q observation=%+v", reason, observation)
	}
	discover := passiveTestEvent("dhcp", "192.168.0.63", "00:11:22:33:44:55", map[string]any{"msg_types": "DISCOVER"})
	if _, reason = passiveObservation(discover, scope); reason == "" {
		t.Fatal("DHCP query created a device observation")
	}
}

func TestPassiveDiscoveryProtocolClassification(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	cases := []struct {
		name, kind, ip, mac, wantType, wantCapability string
		payload                                       map[string]any
	}{
		{name: "arp", kind: "arp", ip: "192.168.0.22", mac: "00:11:22:33:44:22", payload: map[string]any{}},
		{name: "ndp", kind: "ndp", ip: "fe80::22", mac: "00:11:22:33:44:22", payload: map[string]any{}},
		{name: "ssdp gateway", kind: "ssdp", ip: "192.168.0.1", wantType: "gateway", wantCapability: "routing", payload: map[string]any{"nt": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}},
		{name: "ws discovery", kind: "ws_discovery", ip: "192.168.0.9", wantType: "camera", wantCapability: "network_video", payload: map[string]any{"message": "hello", "types": "dn:NetworkVideoTransmitter"}},
		{name: "lldp", kind: "lldp", ip: "192.168.0.2", mac: "00:11:22:33:44:02", wantType: "switch", payload: map[string]any{"system_capabilities": "bridge"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observation, reason := passiveObservation(passiveTestEvent(tc.kind, tc.ip, tc.mac, tc.payload), scope)
			if reason != "" || observation.Origin == "" {
				t.Fatalf("protocol was skipped: %s", reason)
			}
			if observation.DeviceType != tc.wantType {
				t.Fatalf("device type=%q want %q", observation.DeviceType, tc.wantType)
			}
			if tc.wantCapability != "" && (len(observation.Capabilities) != 1 || observation.Capabilities[0] != tc.wantCapability) {
				t.Fatalf("capabilities=%v", observation.Capabilities)
			}
		})
	}
}

func TestPassiveDiscoveryRejectsPublicProtocolEvidence(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	for _, kind := range []string{"arp", "ssdp", "ws_discovery"} {
		_, reason := passiveObservation(passiveTestEvent(kind, "218.30.19.40", "00:11:22:33:44:55", map[string]any{}), scope)
		if reason == "" {
			t.Fatalf("%s created a public-address observation", kind)
		}
	}
}
