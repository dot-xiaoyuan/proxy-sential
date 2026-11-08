package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"

	"github.com/DATA-DOG/go-sqlmock"
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
	if passiveDiscoveryBatchSize <= 0 || passiveDiscoveryBatchSize > 1500 || passiveDiscoveryBatchBytes <= 0 || passiveDiscoveryBatchBytes > 6<<20 {
		t.Fatalf("passive discovery batch must stay bounded, got %d", passiveDiscoveryBatchSize)
	}
	if passiveDiscoveryMinBatch < 500 || passiveDiscoveryMinBatch > passiveDiscoveryBatchSize {
		t.Fatalf("discovery floor must stay high enough to amortise per-batch reads, got %d", passiveDiscoveryMinBatch)
	}
}

func TestPassiveDiscoveryByteBudgetRetainsCompleteCursorPrefix(t *testing.T) {
	first := `{"event_id":"first"}` + "\n"
	second := `{"event_id":"second"}` + "\n"
	raw := []byte(first + second)
	bounded, err := boundedPassiveDiscoveryRows(raw, len(first)+len(second)-1)
	if err != nil || string(bounded) != first || string(raw[len(bounded):]) != second {
		t.Fatalf("byte limit lost or split a row: bounded=%q remainder=%q err=%v", bounded, raw[len(bounded):], err)
	}
	if _, err := boundedPassiveDiscoveryRows(raw, len(first)-1); err == nil {
		t.Fatal("oversized first row was accepted without a complete cursor boundary")
	}
}

func TestPassiveDiscoveryBatchRetriesSmallerAfterTimeout(t *testing.T) {
	tuner := passiveDiscoveryBatchTuner{limit: passiveDiscoveryBatchSize}
	tuner.observe(true, context.DeadlineExceeded)
	if tuner.limit != passiveDiscoveryBatchSize/2 {
		t.Fatalf("timeout should halve the next claim, got %d", tuner.limit)
	}
	for range 3 {
		tuner.observe(true, nil)
	}
	if tuner.limit != passiveDiscoveryBatchSize {
		t.Fatalf("three full successes should restore the cap, got %d", tuner.limit)
	}
	for range 4 {
		tuner.observe(true, context.DeadlineExceeded)
	}
	if tuner.limit != passiveDiscoveryMinBatch {
		t.Fatalf("timeout retries went below minimum bounded claim: %d", tuner.limit)
	}
	tuner.observe(false, context.Canceled)
	if tuner.limit != passiveDiscoveryMinBatch {
		t.Fatalf("non-timeout cancellation changed the batch limit: %d", tuner.limit)
	}
}

func TestPassiveDiscoveryBatchUsesSingleTransaction(t *testing.T) {
	source, err := os.ReadFile("passive_discovery_materializer.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(source)
	for _, fragment := range []string{"processPassiveDiscoveryBatch", "BeginTx(ctx, nil)", "materializeMDNS(ctx, tx", "flushPassiveObservations(ctx, tx", "tx.Commit()"} {
		if !strings.Contains(code, fragment) {
			t.Fatalf("passive discovery batch transaction omitted %q", fragment)
		}
	}
}

func TestPassiveDiscoveryBindingLookupIsIndexed(t *testing.T) {
	migration, err := os.ReadFile("../../migrations/postgres/096_passive_discovery_binding_lookup.sql")
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

func TestPassiveMDNSIgnoresUnusableServiceAnnouncementsButKeepsWithdrawal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope, err := parsePassiveDiscoveryScope("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	event := passiveTestEvent("mdns", "192.168.0.8", "", map[string]any{
		"is_response": true, "record_type": "PTR", "record_name": "_dosvc._tcp.local",
		"service_target": "desktop._dosvc._tcp.local", "ttl": 120,
	})
	if observations, reason, err := (&DBStore{}).materializeMDNS(context.Background(), db, event, scope); err != nil || len(observations) != 0 || reason != "mdns_unusable_service" {
		t.Fatalf("unusable service should not write a discovery projection: observations=%v reason=%q err=%v", observations, reason, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	withdrawn := event
	withdrawn.Payload = map[string]any{
		"is_response": true, "record_type": "PTR", "record_name": "_dosvc._tcp.local",
		"service_target": "desktop._dosvc._tcp.local", "ttl": 0,
	}
	mock.ExpectExec("DELETE FROM passive_discovery_mdns_records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE discovery_observations SET valid_until").WillReturnResult(sqlmock.NewResult(0, 0))
	if _, _, err := (&DBStore{}).materializeMDNS(context.Background(), db, withdrawn, scope); err != nil {
		t.Fatalf("withdrawal must still remove an older service projection: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveMDNSRetainsSupportedServiceAnnouncement(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope, err := parsePassiveDiscoveryScope("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	event := passiveTestEvent("mdns", "192.168.0.8", "", map[string]any{
		"is_response": true, "record_type": "PTR", "record_name": "_ipp._tcp.local",
		"service_target": "printer._ipp._tcp.local", "ttl": 120,
	})
	mock.ExpectExec("INSERT INTO passive_discovery_mdns_records").WillReturnResult(sqlmock.NewResult(0, 1))
	// PTR answers create their observation directly; the SRV/A join only runs
	// for SRV and address answers.
	observations, reason, err := (&DBStore{}).materializeMDNS(context.Background(), db, event, scope)
	if err != nil || reason != "" || len(observations) != 1 || observations[0].Origin != "dns_sd" || observations[0].DeviceType != "printer" {
		t.Fatalf("supported printer service changed: observations=%v reason=%q err=%v", observations, reason, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
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

func TestPassiveDiscoveryRetainsOriginalNormalizedDeviceName(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	event := passiveTestEvent("dhcp", "192.168.0.6", "50:2b:73:d9:70:34", map[string]any{
		"msg_types": "ACK", "hostname": "ld的电脑", "hostname_original": `ld\xb5\xc4\xb5\xe7\xc4\xd4`, "hostname_encoding": "gb18030-escape",
	})
	observation, reason := passiveObservation(event, scope)
	if reason != "" || observation.Name != "ld的电脑" || observation.OriginalName != `ld\xb5\xc4\xb5\xe7\xc4\xd4` || observation.NameEncoding != "gb18030-escape" {
		t.Fatalf("normalized DHCP name evidence was not retained: reason=%q observation=%+v", reason, observation)
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
		{name: "ikuai lldp", kind: "lldp", ip: "0.0.0.0", mac: "00:e0:67:2a:4f:4f", wantType: "router", wantCapability: "routing", payload: map[string]any{"system_name": "iKuai-X86", "system_description": "4.0.310@iKuaiOS", "management_address": "0.0.0.0", "system_capabilities": "station"}},
		{name: "android dhcp", kind: "dhcp", ip: "192.168.0.45", mac: "a2:0c:05:7a:0f:33", wantType: "mobile", payload: map[string]any{"msg_types": "REQUEST,ACK", "hostname": "HBN-AL00", "device_hint": "android", "vendor_class": "HUAWEI:android:HBN"}},
		{name: "vivo model dhcp", kind: "dhcp", ip: "192.168.0.82", mac: "42:59:38:7a:fc:b3", wantType: "mobile", payload: map[string]any{"msg_types": "REQUEST,ACK", "hostname": "vivo-X200-Ultra", "vendor_class": "dhcpcd-16"}},
		{name: "ieee1905 mesh", kind: "ieee1905_topology", ip: "", mac: "00:11:22:33:44:05", wantType: "access_point", wantCapability: "routing", payload: map[string]any{"al_mac": "00:11:22:33:44:05", "vendor_oui": "00:0a:eb"}},
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

func TestPassivePTRDirectL2IdentityRequiresSameMulticastResponder(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	at := time.Now().UTC()
	event := passiveTestEvent("mdns", "192.168.0.254", "", map[string]any{"is_response": true, "l2_source_mac_direct": true, "responder_l2_mac": "02:11:22:33:44:55"})
	event.Source = "zeek"
	event.Flow = map[string]any{"dst_ip": "224.0.0.251"}
	observation, ok := passivePTRObservation(event, "office-30", "ens1f1", "_ipp._tcp.local", "hp laserjet._ipp._tcp.local", at, at.Add(time.Minute), scope)
	if !ok || observation.MAC != "02:11:22:33:44:55" || !passiveDirectResponderIdentity(observation) {
		t.Fatalf("direct responder identity missing: %+v", observation)
	}
	for _, change := range []func(*discovery.Observation){
		func(o *discovery.Observation) { o.Evidence.Payload["l2_source_mac_direct"] = false },
		func(o *discovery.Observation) { o.Evidence.Subject["mac"] = "02:11:22:33:44:66" },
		func(o *discovery.Observation) { o.Evidence.Flow["dst_ip"] = "192.168.0.1" },
		func(o *discovery.Observation) { o.Evidence.Source = "other" },
	} {
		copy := observation
		copy.Evidence = observation.Evidence
		copy.Evidence.Payload = map[string]any{"l2_source_mac_direct": true, "responder_l2_mac": observation.MAC, "service_source": "ptr_responder"}
		copy.Evidence.Subject = map[string]any{"ip": observation.IP, "mac": observation.MAC}
		copy.Evidence.Flow = map[string]any{"dst_ip": "224.0.0.251"}
		change(&copy)
		if passiveDirectResponderIdentity(copy) {
			t.Fatalf("unverified responder accepted: %+v", copy)
		}
	}
}

func TestDirectPTRLinkDoesNotRequireDHCPLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	event := passiveTestEvent("mdns", "192.168.0.254", "", map[string]any{"is_response": true, "l2_source_mac_direct": true, "responder_l2_mac": "02:11:22:33:44:55"})
	event.Source = "zeek"
	event.Flow = map[string]any{"dst_ip": "224.0.0.251"}
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	observation, ok := passivePTRObservation(event, "office-30", "ens1f1", "_ipp._tcp.local", "hp laserjet._ipp._tcp.local", at, at.Add(time.Minute), scope)
	if !ok {
		t.Fatal("expected PTR observation")
	}
	link, err := (&DBStore{}).passiveObservationLink(context.Background(), db, observation)
	if err != nil {
		t.Fatal(err)
	}
	if link == nil || link.EndpointID != "mac:02:11:22:33:44:55" || link.ObservationID != observation.ID {
		t.Fatalf("direct PTR responder must link without a lease, got %+v", link)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
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

func TestPassiveSelfReportReadsUPnPDescription(t *testing.T) {
	manufacturer, model := passiveSelfReport(map[string]any{
		"description": map[string]any{
			"manufacturer": "TP-Link",
			"model_name":   "Archer AX55",
			"model_number": "v1",
		},
	})
	if manufacturer != "TP-Link" || model != "Archer AX55 v1" {
		t.Fatalf("unexpected self-report: %q %q", manufacturer, model)
	}
	if manufacturer, model := passiveSelfReport(map[string]any{"st": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}); manufacturer != "" || model != "" {
		t.Fatalf("service type must not invent a self-report: %q %q", manufacturer, model)
	}
}

func TestPassiveRepeatableFactIDCollapsesWithinHour(t *testing.T) {
	base := time.Date(2026, 11, 7, 10, 5, 0, 0, time.UTC)
	fact := discovery.Observation{ID: "event-1", Origin: "arp", SourceID: "passive:s204:mirror", MAC: "00:11:22:33:44:55", IP: "10.0.0.8", ObservedAt: base}
	sameHour := fact
	sameHour.ObservedAt = base.Add(40 * time.Minute)
	nextHour := fact
	nextHour.ObservedAt = base.Add(2 * time.Hour)
	otherAddress := fact
	otherAddress.IP = "10.0.0.9"

	first := passiveRepeatableFactID(fact)
	if first == "" || first != passiveRepeatableFactID(sameHour) {
		t.Fatalf("same fact in one hour must share an observation id: %q %q", first, passiveRepeatableFactID(sameHour))
	}
	if first != passiveRepeatableFactID(nextHour) {
		t.Fatal("an active fact must keep one row across hours")
	}
	if first == passiveRepeatableFactID(otherAddress) {
		t.Fatal("a different address must be a different fact")
	}
	if id := passiveRepeatableFactID(discovery.Observation{Origin: "ssdp", MAC: "00:11:22:33:44:55"}); id != "" {
		t.Fatalf("non-repeatable origins keep their event id, got %q", id)
	}
}

func TestPassiveLinkRefreshIsThrottled(t *testing.T) {
	for _, path := range []string{"passive_discovery_materializer.go", "passive_arp_batch.go"} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		code := string(source)
		if !strings.Contains(code, "EXCLUDED.valid_until>discovery_identity_links.valid_until+interval '5 minutes'") || !strings.Contains(code, "discovery_identity_links.endpoint_id IS DISTINCT FROM EXCLUDED.endpoint_id") {
			t.Fatalf("%s must throttle repeated identity-link refreshes", path)
		}
	}
}

func TestPassiveLinkBatchDeduplicatesObservationIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	mock.ExpectExec("WITH incoming").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 2))
	links := []passiveLinkRow{
		{ObservationID: "fact-a", EndpointID: "mac:00:11:22:33:44:55", ValidUntil: at, Basis: []byte(`{}`)},
		{ObservationID: "fact-a", EndpointID: "mac:00:11:22:33:44:55", ValidUntil: at.Add(time.Hour), Basis: []byte(`{}`)},
	}
	if err := (&DBStore{}).insertPassiveLinksBatch(context.Background(), db, links); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveDiscoveryTTLOSHint(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("192.168.0.0/24")
	for _, tc := range []struct {
		ttl  int
		want string
	}{
		{126, "Windows"},
		{128, "Windows"},
		{63, "Unix"},
		{64, "Unix"},
		{254, ""},
	} {
		observation, reason := passiveObservation(passiveTestEvent("ttl", "", "", map[string]any{"ttl": tc.ttl, "neighbor_mac": "00:11:22:33:44:66"}), scope)
		if reason != "" || observation.Origin != "ttl" || observation.OSHint != tc.want || observation.MAC != "00:11:22:33:44:66" {
			t.Fatalf("ttl=%d: reason=%q observation=%+v", tc.ttl, reason, observation)
		}
	}
}
