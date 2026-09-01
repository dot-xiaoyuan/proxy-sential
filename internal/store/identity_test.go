package store

import (
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestBuildIdentityStateKeepsDynamicIPOnSameEndpoint(t *testing.T) {
	events := []normalized.Event{
		identityStoreEvent("id-1", "2026000123", "10.20.15.83", "aa:bb:cc:dd:ee:01", "Dorm-A-AP01", "endpoint", "sess-1", "2026-07-29T10:00:00Z"),
		identityStoreEvent("id-2", "2026000123", "10.20.16.44", "aa:bb:cc:dd:ee:01", "Dorm-A-AP01", "endpoint", "sess-1", "2026-07-29T10:05:00Z"),
	}

	state := BuildIdentityState(events)
	if len(state.Endpoints) != 1 {
		t.Fatalf("expected one endpoint across dynamic IP changes, got %+v", state.Endpoints)
	}
	if state.Endpoints[0].EndpointID != "mac:aa:bb:cc:dd:ee:01" || state.Endpoints[0].FirstSeen != "2026-07-29T10:00:00Z" || state.Endpoints[0].LastSeen != "2026-07-29T10:05:00Z" {
		t.Fatalf("unexpected endpoint state: %+v", state.Endpoints[0])
	}
	if len(state.IPMACHistory) != 2 {
		t.Fatalf("expected two IP/MAC history facts, got %+v", state.IPMACHistory)
	}
	if len(state.Sessions) != 1 || state.Sessions[0].SessionID != "sess-1" {
		t.Fatalf("expected one deduped account session, got %+v", state.Sessions)
	}
}

func TestBuildIdentityStateExcludesInfrastructureFromEndpointSessions(t *testing.T) {
	events := []normalized.Event{
		identityStoreEvent("infra-gw", "system", "10.20.0.1", "", "core-gateway", "gateway", "", "2026-07-29T10:00:00Z"),
		identityStoreEvent("infra-dns", "system", "10.20.0.2", "", "dns-rack", "server", "", "2026-07-29T10:05:00Z"),
	}

	state := BuildIdentityState(events)
	if len(state.Endpoints) != 0 || len(state.Sessions) != 0 {
		t.Fatalf("infrastructure should not create endpoint/session state: %+v", state)
	}
	if len(state.Infrastructure) != 2 {
		t.Fatalf("expected infrastructure entities, got %+v", state.Infrastructure)
	}
	if len(state.IPMACHistory) != 0 {
		t.Fatalf("infrastructure should not create endpoint IP/MAC history, got %+v", state.IPMACHistory)
	}
}

func TestBuildIdentityStateCreatesEndpointCandidateFromDeviceEvent(t *testing.T) {
	events := []normalized.Event{{
		SchemaVersion:   "v1",
		EventID:         "zeek-dhcp-1",
		Source:          "zeek",
		SourceEventType: "dhcp",
		Type:            "device",
		Timestamp:       "2026-08-21T10:00:00Z",
		Subject:         map[string]any{"ip": "192.168.0.21", "mac": "AA-BB-CC-DD-EE-01"},
		Flow:            map[string]any{"src_ip": "192.168.0.21"},
		Payload:         map[string]any{"origin": "dhcp", "hostname": "office-laptop", "vendor_class": "MSFT 5.0"},
		Confidence:      0.9,
	}}

	state := BuildIdentityState(events)
	if len(state.Endpoints) != 1 {
		t.Fatalf("expected one endpoint candidate, got %+v", state.Endpoints)
	}
	endpoint := state.Endpoints[0]
	if endpoint.EndpointID != "mac:aa:bb:cc:dd:ee:01" || endpoint.PrimaryMAC != "aa:bb:cc:dd:ee:01" || endpoint.RegistrationStatus != "unregistered" {
		t.Fatalf("unexpected endpoint candidate: %+v", endpoint)
	}
	if endpoint.Attributes["hostname"] != "office-laptop" || endpoint.Attributes["vendor_class"] != "MSFT 5.0" {
		t.Fatalf("expected DHCP identity hints, got %+v", endpoint.Attributes)
	}
	if len(state.IPMACHistory) != 1 || state.IPMACHistory[0].IP != "192.168.0.21" {
		t.Fatalf("expected one IP/MAC history entry, got %+v", state.IPMACHistory)
	}
	if len(state.Sessions) != 0 {
		t.Fatalf("device discovery must not invent account sessions: %+v", state.Sessions)
	}
}

func TestBuildIdentityStateIgnoresDeviceEventWithoutMAC(t *testing.T) {
	state := BuildIdentityState([]normalized.Event{{
		EventID: "zeek-software-1", Type: "device", Timestamp: "2026-08-21T10:00:00Z",
		Subject: map[string]any{"ip": "192.168.0.21"}, Payload: map[string]any{"origin": "software"},
	}})
	if len(state.Endpoints) != 0 || len(state.IPMACHistory) != 0 {
		t.Fatalf("MAC-less software observations must not create unstable endpoint identities: %+v", state)
	}
}

func TestEndpointInventoryIncludesConservativeFingerprintRecognition(t *testing.T) {
	state := BuildIdentityState([]normalized.Event{{
		SchemaVersion: "v1", EventID: "device-mi9se", Source: "zeek", Type: "device", Timestamp: "2026-08-21T10:00:00Z",
		Subject: map[string]any{"ip": "192.168.0.35", "mac": "e6:c4:00:00:00:01"},
		Payload: map[string]any{"origin": "dhcp", "hostname": "MI9SE-xiaoyingderead", "vendor_class": "android-dhcp-10"}, Confidence: 0.9,
	}})
	items := BuildEndpointDeviceInventories(state, Query{})
	if len(items) != 1 {
		t.Fatalf("expected one endpoint inventory, got %+v", items)
	}
	item := items[0]
	if item.Brand != "Xiaomi" || item.Model != "Mi 9 SE" || item.DeviceType != "mobile" || !item.RandomizedMAC {
		t.Fatalf("unexpected endpoint recognition: %+v", item)
	}
}

func identityStoreEvent(eventID, accountID, ip, mac, accessID, entityRole, sessionID, timestamp string) normalized.Event {
	subject := map[string]any{
		"ip":                  ip,
		"account_id":          accountID,
		"access_id":           accessID,
		"entity_role":         entityRole,
		"identity_confidence": 0.92,
	}
	if mac != "" {
		subject["mac"] = mac
		subject["endpoint_id"] = "mac:" + mac
	} else {
		subject["endpoint_id"] = "infra:" + accessID
	}
	payload := map[string]any{
		"origin": "radius",
		"ap":     accessID,
	}
	if sessionID != "" {
		payload["session_id"] = sessionID
	}
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID,
		Source:          "radius",
		SourceEventType: "identity",
		Type:            "identity",
		Timestamp:       timestamp,
		Observer:        map[string]any{"sensor_id": "test"},
		Subject:         subject,
		Flow:            map[string]any{"src_ip": ip, "dst_ip": "0.0.0.0", "proto": "other", "direction": "unknown"},
		Payload:         payload,
		Confidence:      0.92,
		RawRef:          map[string]any{"backend": "radius"},
	}
}
