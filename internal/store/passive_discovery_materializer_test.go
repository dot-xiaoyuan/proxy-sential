package store

import (
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func TestPassiveDiscoveryUsesBoundedSignalStream(t *testing.T) {
	source, err := os.ReadFile("passive_discovery_materializer.go")
	if err != nil {
		t.Fatal(err)
	}
	querySource := string(source)
	if !strings.Contains(querySource, "FROM passive_discovery_events_v2 PREWHERE") || strings.Contains(querySource, "FROM normalized_events PREWHERE") {
		t.Fatal("passive materializer must not scan the general normalized event table")
	}
}

func TestPassiveDiscoveryBatchFitsLeaseBudget(t *testing.T) {
	if passiveDiscoveryBatchSize <= 0 || passiveDiscoveryBatchSize > 500 {
		t.Fatalf("passive discovery batch must stay bounded, got %d", passiveDiscoveryBatchSize)
	}
}

func TestPassiveDiscoveryBindingLookupIsIndexed(t *testing.T) {
	migration, err := os.ReadFile("../../migrations/postgres/072_passive_discovery_binding_lookup.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(migration)
	for _, fragment := range []string{"discovery_observation_binding_lookup", "(data->>'node')", "(data->>'ip')", "origin IN ('dhcp','arp','ndp')"} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("binding lookup migration omitted %q", fragment)
		}
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

func TestPassivePTRResponseCreatesServiceWithoutTerminalIdentity(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	at := time.Now().UTC()
	event := passiveTestEvent("mdns", "192.168.0.254", "", map[string]any{"is_response": true})
	observation, ok := passivePTRObservation(event, "office-30", "ens1f1", "_ipp._tcp.local", "hp laserjet pro mfp m128fw[5df46c]._ipp._tcp.local", at, at.Add(120*time.Second), scope)
	if !ok || observation.DeviceType != "printer" || len(observation.Capabilities) != 1 || observation.Capabilities[0] != "printing" || observation.IP != "192.168.0.254" {
		t.Fatalf("unexpected PTR observation: %+v", observation)
	}
	if observation.MAC != "" || observation.Evidence.Subject["mac"] != nil {
		t.Fatal("PTR service response manufactured a terminal identity")
	}
	event.Subject["ip"] = "218.30.19.40"
	if _, ok = passivePTRObservation(event, "office-30", "ens1f1", "_ipp._tcp.local", "hp laserjet._ipp._tcp.local", at, at.Add(time.Minute), scope); ok {
		t.Fatal("public PTR responder created a discovery observation")
	}
}

func TestPassiveHostTokenRequiresStableHexSuffix(t *testing.T) {
	if token := passiveHostToken("dev5df46c.local"); token != "5df46c" {
		t.Fatalf("token=%q", token)
	}
	for _, name := range []string{"printer.local", "dev123.local", "office-xyz.local"} {
		if token := passiveHostToken(name); token != "" {
			t.Fatalf("weak host token %q from %q", token, name)
		}
	}
}

func TestPassiveDNSServiceTargetMergesIPv4AndIPv6(t *testing.T) {
	base := passiveTestEvent("mdns", "192.168.0.254", "", map[string]any{})
	base.Payload = map[string]any{"service_target": "dev5df46c.local"}
	first := discovery.Observation{SourceID: "passive:office-30:ens1f1", Origin: "dns_sd", IP: "192.168.0.254", Evidence: base}
	second := first
	second.IP = "fe80::ca5a:cfff:fe5d:f46c"
	second.Interface = "ens1f1"
	if first.Key() != second.Key() {
		t.Fatal("DNS-SD service target addresses were split into separate devices")
	}
}
