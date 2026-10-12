package store

import (
	"context"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func protocolAttributionHTTPEvent(id, ip, at string) normalized.Event {
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         id,
		Source:          "zeek",
		SourceEventType: "http",
		Type:            "http",
		Timestamp:       at,
		Observer:        map[string]any{"sensor_id": "protocol-test"},
		Subject:         map[string]any{"ip": ip, "campus_id": "campus-a"},
		Flow:            map[string]any{"src_ip": ip, "dst_ip": "198.18.91.1", "src_port": 51000, "dst_port": 80, "proto": "tcp", "direction": "outbound"},
		Payload:         map[string]any{"server": "HP HTTP Server; HP LaserJet M426fdw", "title": "HP LaserJet M426fdw", "user_agent": "Mozilla/5.0", "method": "GET"},
		Confidence:      0.9,
	}
}

func protocolAttributionTLSEvent(id, ip, at string) normalized.Event {
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         id,
		Source:          "zeek",
		SourceEventType: "ssl",
		Type:            "tls",
		Timestamp:       at,
		Observer:        map[string]any{"sensor_id": "protocol-test"},
		Subject:         map[string]any{"ip": ip, "campus_id": "campus-a"},
		Flow:            map[string]any{"src_ip": ip, "dst_ip": "198.18.91.1", "proto": "tcp", "direction": "outbound"},
		Payload:         map[string]any{"certificate_subject": "CN=HP LaserJet M426fdw", "certificate_issuer": "CN=HP", "certificate_san": "printer.local", "ja3": "abcdef0123456789", "sni": "printer.local"},
		Confidence:      0.9,
	}
}

func protocolAttributionLease(id, ip, mac, at, action string) normalized.Event {
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         id,
		Source:          "zeek",
		SourceEventType: "dhcp",
		Type:            "device",
		Timestamp:       at,
		Observer:        map[string]any{"sensor_id": "protocol-test"},
		Subject:         map[string]any{"ip": ip, "mac": mac, "campus_id": "campus-a"},
		Payload:         map[string]any{"origin": "dhcp", "assigned_addr": ip, "msg_types": action, "lease_time": "600", "lease_observed_at": at},
		Confidence:      0.9,
	}
}

// Derived protocol events must carry only whitelisted self-report fields so a
// derived event cannot leak unrelated payload into device recognition.
func TestProtocolAttributionPayloadKeepsWhitelistedFieldsOnly(t *testing.T) {
	event := protocolAttributionHTTPEvent("http-1", "198.18.91.10", "2026-10-11T10:00:00Z")
	payload := protocolAttributionPayload(event, protocolAttributionPayloadKeys["http"])
	if payload == nil {
		t.Fatal("expected payload")
	}
	for _, key := range []string{"server", "title", "origin", "derived", "campus_id"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("missing %q in %+v", key, payload)
		}
	}
	for _, key := range []string{"user_agent", "method"} {
		if _, ok := payload[key]; ok {
			t.Fatalf("leaked %q into %+v", key, payload)
		}
	}
	if payload["origin"] != "http" || payload["derived"] != protocolAttributionOrigin {
		t.Fatalf("unexpected markers: %+v", payload)
	}
	empty := protocolAttributionPayload(normalized.Event{Type: "http", Payload: map[string]any{"method": "GET"}}, protocolAttributionPayloadKeys["http"])
	if empty != nil {
		t.Fatalf("event without self-report produced %+v", empty)
	}
}

// The derived identifier must be stable and traceable to the source event.
func TestProtocolDeviceEventIsStableAndTraceable(t *testing.T) {
	event := protocolAttributionTLSEvent("tls-1", "198.18.91.10", "2026-10-11T10:00:00Z")
	observation := protocolAttributionObservations(event)[0]
	payload := observation.Payload
	first := protocolDeviceEvent(observation, "02:00:00:00:91:10", payload)
	second := protocolDeviceEvent(observation, "02:00:00:00:91:10", payload)
	if first.EventID != second.EventID || first.EventID == "" {
		t.Fatalf("unstable identifier: %q vs %q", first.EventID, second.EventID)
	}
	if first.Type != "device" || first.Subject["mac"] != "02:00:00:00:91:10" || first.Subject["entity_role"] != "endpoint" {
		t.Fatalf("unexpected derived subject: %+v", first)
	}
	if first.RawRef["derived_from"] != "tls-1" || first.RawRef["reason"] != protocolAttributionOrigin {
		t.Fatalf("missing traceability: %+v", first.RawRef)
	}
	if first.Flow["src_ip"] != "198.18.91.10" || first.Flow["proto"] != "tcp" {
		t.Fatalf("flow not preserved: %+v", first.Flow)
	}
}

// Protocol self-report must surface as its own signal kinds, and must not be
// mistaken for a hostname, model or DHCP-derived hint.
func TestProtocolAttributionSignalKinds(t *testing.T) {
	event := protocolAttributionHTTPEvent("http-1", "198.18.91.10", "2026-10-11T10:00:00Z")
	httpObservation := protocolAttributionObservations(event)[0]
	derived := protocolDeviceEvent(httpObservation, "02:00:00:00:91:10", httpObservation.Payload)
	kinds := map[string]string{}
	for _, draft := range signalDrafts(derived) {
		kinds[draft.kind] = draft.value
	}
	if kinds["http_server"] != "HP HTTP Server; HP LaserJet M426fdw" {
		t.Fatalf("missing http_server signal: %+v", kinds)
	}
	if kinds["http_title"] != "HP LaserJet M426fdw" {
		t.Fatalf("missing http_title signal: %+v", kinds)
	}
	if _, ok := kinds["device_name"]; ok {
		t.Fatalf("http title leaked into device_name: %+v", kinds)
	}
	if _, ok := kinds["os_family"]; ok {
		t.Fatalf("protocol self-report produced an OS guess: %+v", kinds)
	}

	tlsObservations := protocolAttributionObservations(protocolAttributionTLSEvent("tls-1", "198.18.91.10", "2026-10-11T10:00:00Z"))
	tlsDerived := protocolDeviceEvent(tlsObservations[0], "02:00:00:00:91:01", tlsObservations[0].Payload)
	tlsKinds := map[string]string{}
	for _, draft := range signalDrafts(tlsDerived) {
		tlsKinds[draft.kind] = draft.value
	}
	if tlsKinds["tls_subject"] != "CN=HP LaserJet M426fdw" || tlsKinds["tls_issuer"] != "CN=HP" {
		t.Fatalf("missing TLS signals: %+v", tlsKinds)
	}
	if tlsKinds["ja3"] != "" {
		t.Fatalf("client JA3 leaked into server signals: %+v", tlsKinds)
	}
	client := protocolDeviceEvent(tlsObservations[1], "02:00:00:00:91:10", tlsObservations[1].Payload)
	clientKinds := map[string]string{}
	for _, draft := range signalDrafts(client) {
		clientKinds[draft.kind] = draft.value
	}
	if clientKinds["ja3"] != "abcdef0123456789" || clientKinds["tls_subject"] != "" {
		t.Fatalf("client fingerprint missing or polluted: %+v", clientKinds)
	}
}

// Events without a usable address or sensor must be skipped before any lease
// lookup: an unparsable address would fail the inet cast and abort the batch.
func TestProtocolAttributionSkipsUnusableAddresses(t *testing.T) {
	s := &PostgresStore{}
	missingSensor := protocolAttributionHTTPEvent("no-sensor", "198.18.91.10", "2026-10-11T10:01:00Z")
	missingSensor.Observer = nil
	noIP := protocolAttributionHTTPEvent("no-ip", "", "2026-10-11T10:01:00Z")
	noIP.Flow["dst_ip"] = ""
	badIP := protocolAttributionHTTPEvent("bad-ip", "not-an-address", "2026-10-11T10:01:00Z")
	badIP.Flow["dst_ip"] = "not-an-address"
	derived, err := s.protocolDeviceEvents(context.Background(), []normalized.Event{
		noIP, badIP,
		missingSensor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(derived) != 0 {
		t.Fatalf("expected no derived events, got %+v", derived)
	}
}

// Attribution only accepts a unique live DHCP lease. Missing and conflicting
// leases must be dropped rather than guessed from the address.
func TestPostgresProtocolLeaseAttribution(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated postgres required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn, SensorID: "protocol-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cleanup := func() {
		for _, statement := range []string{
			`DELETE FROM device_signal_events WHERE sensor_id='protocol-test'`,
			`DELETE FROM device_signal_facts WHERE sensor_id='protocol-test'`,
			`DELETE FROM device_address_leases WHERE sensor_id='protocol-test'`,
			`DELETE FROM endpoint_device_profiles WHERE endpoint_id LIKE 'mac:02:00:00:00:91:%'`,
			`DELETE FROM endpoint_entities WHERE endpoint_id LIKE 'mac:02:00:00:00:91:%'`,
		} {
			_, _ = s.db.ExecContext(ctx, statement)
		}
	}
	cleanup()
	defer cleanup()
	if _, err = s.db.ExecContext(ctx, `INSERT INTO sensors(sensor_id,display_name,collector_kind) VALUES('protocol-test','protocol-test','zeek') ON CONFLICT(sensor_id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}

	const leasedIP = "198.18.91.10"
	const mac = "02:00:00:00:91:10"
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{protocolAttributionLease("lease-a", leasedIP, mac, "2026-10-11T10:00:00Z", "ACK")}); err != nil {
		t.Fatal(err)
	}

	if err = s.WriteIdentityEvents(ctx, []normalized.Event{protocolAttributionLease("lease-client", "198.18.91.50", "02:00:00:00:91:50", "2026-10-11T10:00:00Z", "ACK")}); err != nil {
		t.Fatal(err)
	}
	http := protocolAttributionHTTPEvent("http-1", leasedIP, "2026-10-11T10:01:00Z")
	tls := protocolAttributionTLSEvent("tls-1", leasedIP, "2026-10-11T10:02:00Z")
	orphan := protocolAttributionHTTPEvent("http-orphan", "198.18.91.50", "2026-10-11T10:01:00Z")
	orphan.Flow["dst_ip"] = "198.18.91.99"
	for _, event := range []*normalized.Event{&http, &tls} {
		event.Subject["ip"] = "198.18.91.50"
		event.Flow["src_ip"] = "198.18.91.50"
		event.Flow["dst_ip"] = leasedIP
	}

	derived, err := s.pgProtocolDeviceEventsForTest(t, ctx, []normalized.Event{http, tls, orphan})
	if err != nil {
		t.Fatal(err)
	}
	if len(derived) != 3 {
		t.Fatalf("expected two server events and one client fingerprint, got %d: %+v", len(derived), derived)
	}
	for _, event := range derived {
		expectedMAC := mac
		if event.Payload["attribution_side"] == "client" {
			expectedMAC = "02:00:00:00:91:50"
		}
		if event.Subject["mac"] != expectedMAC {
			t.Fatalf("unexpected attribution: %+v", event.Subject)
		}
	}
	if err = s.WriteProtocolDeviceEvents(ctx, derived); err != nil {
		t.Fatal(err)
	}
	// Replaying the same batch must stay idempotent.
	if err = s.WriteProtocolDeviceEvents(ctx, derived); err != nil {
		t.Fatal(err)
	}

	var brand, deviceType string
	if err = s.db.QueryRowContext(ctx, `SELECT COALESCE(brand,''),COALESCE(device_type,'') FROM endpoint_device_profiles WHERE endpoint_id='mac:`+mac+`'`).Scan(&brand, &deviceType); err != nil {
		t.Fatalf("endpoint profile missing: %v", err)
	}
	if brand != "HP" || deviceType != "printer" {
		t.Fatalf("expected HP printer from protocol self-report, got brand=%q type=%q", brand, deviceType)
	}

	if err = s.db.QueryRowContext(ctx, `SELECT COALESCE(brand,''),COALESCE(device_type,'') FROM endpoint_device_profiles WHERE endpoint_id='mac:02:00:00:00:91:50'`).Scan(&brand, &deviceType); err != nil {
		t.Fatal(err)
	}
	if brand == "HP" || deviceType == "printer" {
		t.Fatalf("client inherited server profile: brand=%q type=%q", brand, deviceType)
	}

	var serverSignals, tlsSignals int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE kind='http_server'),count(*) FILTER(WHERE kind='tls_subject') FROM device_signal_facts WHERE sensor_id='protocol-test' AND host(ip)=$1`, leasedIP).Scan(&serverSignals, &tlsSignals); err != nil {
		t.Fatal(err)
	}
	if serverSignals != 1 || tlsSignals != 1 {
		t.Fatalf("expected http_server and tls_subject facts, got %d/%d", serverSignals, tlsSignals)
	}

	// A simultaneous conflicting lease must block attribution instead of
	// picking one owner.
	other := protocolAttributionLease("lease-b", leasedIP, "02:00:00:00:91:11", "2026-10-11T10:00:00Z", "ACK")
	if err = s.WriteIdentityEvents(ctx, []normalized.Event{other}); err != nil {
		t.Fatal(err)
	}
	conflictingHTTP := protocolAttributionHTTPEvent("http-2", "198.18.91.50", "2026-10-11T10:04:00Z")
	conflictingHTTP.Flow["dst_ip"] = leasedIP
	afterConflict, err := s.pgProtocolDeviceEventsForTest(t, ctx, []normalized.Event{conflictingHTTP})
	if err != nil {
		t.Fatal(err)
	}
	if len(afterConflict) != 0 {
		t.Fatalf("ambiguous lease was attributed: %+v", afterConflict)
	}
}

// pgProtocolDeviceEventsForTest exposes the resolution step without changing
// production visibility.
func (s *PostgresStore) pgProtocolDeviceEventsForTest(t *testing.T, ctx context.Context, events []normalized.Event) ([]normalized.Event, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.protocolDeviceEvents(ctx, events)
}

// A request's subject is its client. Server headers and certificates must never
// identify that client; only client fingerprints belong to the source address.
func TestProtocolAttributionSeparatesClientAndServer(t *testing.T) {
	http := protocolAttributionHTTPEvent("http-direction", "198.18.91.10", "2026-10-12T00:00:00Z")
	tls := protocolAttributionTLSEvent("tls-direction", "198.18.91.10", http.Timestamp)
	tls.Flow["dst_ip"] = "198.18.91.1"
	for _, event := range []normalized.Event{http, tls} {
		observations := protocolAttributionObservations(event)
		for _, observation := range observations {
			ip := stringFromMap(observation.Subject, "ip")
			if stringFromMap(observation.Payload, "server") != "" || stringFromMap(observation.Payload, "certificate_subject") != "" {
				if ip != "198.18.91.1" {
					t.Fatalf("server evidence attributed to client: %+v", observation)
				}
				if stringFromMap(observation.Payload, "ja3") != "" {
					t.Fatal("client fingerprint leaked into server evidence")
				}
			}
			if stringFromMap(observation.Payload, "ja3") != "" && ip != "198.18.91.10" {
				t.Fatal("client fingerprint attributed to server")
			}
		}
		if len(observations) == 0 {
			t.Fatal("expected attributed observations")
		}
	}
}

func TestProtocolAttributionDropsUnlocatedServer(t *testing.T) {
	event := protocolAttributionTLSEvent("missing-peer", "198.18.91.10", "2026-10-12T00:00:00Z")
	delete(event.Payload, "ja3")
	delete(event.Flow, "dst_ip")
	if got := protocolAttributionObservations(event); len(got) != 0 {
		t.Fatalf("guessed certificate owner from client: %+v", got)
	}
	event.SourceEventType = "x509"
	event.Flow["dst_ip"] = event.Subject["ip"]
	if got := protocolAttributionObservations(event); len(got) != 0 {
		t.Fatal("legacy duplicated client address cannot prove certificate ownership")
	}
	event.Payload["certificate_owner_ip"] = event.Subject["ip"]
	if got := protocolAttributionObservations(event); len(got) != 1 || got[0].Subject["ip"] != "198.18.91.10" {
		t.Fatalf("host-scoped certificate lost: %+v", got)
	}
}

func TestProtocolDerivedIDsDistinguishSides(t *testing.T) {
	event := protocolAttributionTLSEvent("same-event", "198.18.91.10", "2026-10-12T00:00:00Z")
	event.Flow["dst_ip"] = "198.18.91.1"
	observations := protocolAttributionObservations(event)
	if len(observations) != 2 {
		t.Fatalf("expected two sides, got %d", len(observations))
	}
	a := protocolDeviceEvent(observations[0], "02:00:00:00:91:10", observations[0].Payload)
	b := protocolDeviceEvent(observations[1], "02:00:00:00:91:01", observations[1].Payload)
	if a.EventID == b.EventID {
		t.Fatal("client and server observations collide")
	}
}

func TestProtocolAttributionDoesNotTurnRequesterIntoPrinter(t *testing.T) {
	event := protocolAttributionTLSEvent("printer-access", "198.18.91.10", "2026-10-12T00:00:00Z")
	event.Flow["dst_ip"] = "198.18.91.1"
	var derived []normalized.Event
	for _, observation := range protocolAttributionObservations(event) {
		mac := "02:00:00:00:91:10"
		if observation.Subject["ip"] == "198.18.91.1" {
			mac = "02:00:00:00:91:01"
		}
		derived = append(derived, protocolDeviceEvent(observation, mac, observation.Payload))
	}
	inventories := BuildEndpointDeviceInventories(BuildIdentityState(derived), Query{})
	if len(inventories) != 2 {
		t.Fatalf("expected two endpoints, got %+v", inventories)
	}
	for _, item := range inventories {
		if item.CurrentIP == "198.18.91.10" && (item.Brand == "HP" || item.DeviceType == "printer") {
			t.Fatalf("requester became a printer: %+v", item)
		}
		if item.CurrentIP == "198.18.91.1" && (item.Brand != "HP" || item.DeviceType != "printer") {
			t.Fatalf("responder lost its certificate evidence: %+v", item)
		}
	}
}
