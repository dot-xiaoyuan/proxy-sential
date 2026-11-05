package discovery

import (
	"encoding/json"
	"os"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func TestNewDeviceViewSerializesEmptyCollectionsAsArrays(t *testing.T) {
	data, err := json.Marshal(newDeviceView("device-test", time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"addresses", "address_details", "capabilities", "protocols", "observations"} {
		if !strings.Contains(string(data), `"`+field+`":[]`) {
			t.Fatalf("%s must be an empty array: %s", field, data)
		}
	}
}

func passiveRepositoryRow(key, ip, mac, name, instance, target string, at time.Time) deviceObservationRow {
	return deviceObservationRow{DeviceKey: key, Observation: Observation{
		ID: key, SourceID: "passive:office-30:ens1f1", Node: "office-30", Site: "office-30", Domain: "ens1f1",
		IP: ip, MAC: mac, Name: name, Origin: "dns_sd", Interface: "ens1f1", Confidence: "strong",
		Capabilities: []string{"printing"}, ObservedAt: at, ValidUntil: at.Add(time.Hour),
		Evidence: normalized.Event{Payload: map[string]any{"service_instance": instance, "service_target": target}},
	}}
}

func TestAggregateDeviceRowsMergesServiceAddressesWithOneIdentity(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	rows := []deviceObservationRow{
		passiveRepositoryRow("mac-key", "192.168.0.254", "c8:5a:cf:5d:f4:6c", "hp laserjet pro mfp m128fw[5df46c]", "hp laserjet pro mfp m128fw[5df46c]._ipp._tcp.local", "dev5df46c.local", at),
		passiveRepositoryRow("service-key", "fe80::ca5a:cfff:fe5d:f46c", "", "hp laserjet pro mfp m128fw[5df46c]", "hp laserjet pro mfp m128fw[5df46c]._ipp._tcp.local", "dev5df46c.local", at.Add(time.Second)),
	}
	items := aggregateDeviceRows(rows, at.Add(time.Minute))
	if len(items) != 1 {
		t.Fatalf("same service device split into %d rows: %+v", len(items), items)
	}
	if items[0].MAC != "c8:5a:cf:5d:f4:6c" || len(items[0].Addresses) != 2 || items[0].PrimaryIP != "192.168.0.254" {
		t.Fatalf("merged identity is incomplete: %+v", items[0])
	}
	if len(items[0].AddressDetails) != 2 || items[0].AddressDetails[0].Family != "ipv4" || !items[0].AddressDetails[0].Primary || items[0].AddressDetails[1].Scope != "link_local" {
		t.Fatalf("structured addresses are incomplete: %+v", items[0].AddressDetails)
	}
}

func TestAggregateDeviceRowsNormalizesLegacyNameForDisplay(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	row := passiveRepositoryRow("legacy-name", "192.168.0.6", "50:2b:73:d9:70:34", `ld\xb5\xc4\xb5\xe7\xc4\xd4`, "", "", at)
	items := aggregateDeviceRows([]deviceObservationRow{row}, at.Add(time.Minute))
	if len(items) != 1 || items[0].Name != "ld的电脑" || items[0].Observations[0].OriginalName != `ld\xb5\xc4\xb5\xe7\xc4\xd4` {
		t.Fatalf("legacy name was not normalized with raw evidence retained: %+v", items)
	}
}

func TestAggregateDeviceRowsClassifiesReliableEndpointProfile(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	row := passiveRepositoryRow("phone", "192.168.0.45", "00:11:22:33:44:45", "phone", "", "", at)
	row.EndpointID, row.ProfileDeviceType, row.ProfileTypeConfidence = "mac:00:11:22:33:44:45", "mobile", .82
	items := aggregateDeviceRows([]deviceObservationRow{row}, at.Add(time.Minute))
	if len(items) != 1 || items[0].DeviceType != "mobile" || items[0].Category != "mobile" {
		t.Fatalf("reliable profile type was not applied: %+v", items)
	}
	row.ProfileTypeConfidence = .79
	items = aggregateDeviceRows([]deviceObservationRow{row}, at.Add(time.Minute))
	if items[0].DeviceType != "" || items[0].Category != "identity_only" {
		t.Fatalf("low-confidence profile type must not be promoted: %+v", items[0])
	}
	row.ProfileTypeConfidence = .82
	row.ProfileConflict = true
	items = aggregateDeviceRows([]deviceObservationRow{row}, at.Add(time.Minute))
	if items[0].DeviceType != "" || items[0].Category != "identity_only" {
		t.Fatalf("conflicting profile type must not be promoted: %+v", items[0])
	}
}

func TestAggregateDeviceRowsReclassifiesExplicitLegacyEvidence(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	phone := passiveRepositoryRow("phone", "192.168.0.82", "42:59:38:7a:fc:b3", "vivo-X200-Ultra", "", "", at)
	phone.Observation.Origin = "dhcp"
	phone.Observation.Evidence.Payload = map[string]any{"hostname": "vivo-X200-Ultra", "vendor_class": "dhcpcd-16"}
	router := passiveRepositoryRow("router", "", "00:e0:67:2a:4f:4f", "iKuai-X86", "", "", at)
	router.Observation.Origin = "lldp"
	router.Observation.Capabilities = nil
	router.Observation.Evidence.Payload = map[string]any{"system_description": "4.0.310@iKuaiOS"}
	items := aggregateDeviceRows([]deviceObservationRow{phone, router}, at.Add(time.Minute))
	if len(items) != 2 {
		t.Fatalf("explicit devices merged unexpectedly: %+v", items)
	}
	categories := map[string]string{}
	for _, item := range items {
		categories[item.Name] = item.Category
	}
	if categories["vivo-X200-Ultra"] != "mobile" || categories["iKuai-X86"] != "network" {
		t.Fatalf("legacy explicit evidence was not reclassified: %+v", items)
	}
}

func TestDeviceViewSerializesHistoricalAddressEvidenceSeparately(t *testing.T) {
	view := newDeviceView("ikuai", time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC))
	view.HistoricalAddresses = []HistoricalAddress{{Value: "192.168.15.1", LastSeen: time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)}}
	data, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"primary_ip":"192.168.15.1"`) || !strings.Contains(string(data), `"historical_addresses":[{"value":"192.168.15.1"`) {
		t.Fatalf("historical address must not be promoted to a current primary address: %s", data)
	}
}

func TestDiscoveryReadQueryUsesCurrentRecognitionAndExactDHCPLeaseLink(t *testing.T) {
	source, err := os.ReadFile("repository.go")
	if err != nil {
		t.Fatal(err)
	}
	query := string(source)
	for _, fragment := range []string{"endpoint_recognition_summary", "dl.event_id=l.id", "coalesce(i.endpoint_id,dl.endpoint_id,'')"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("discovery read query omitted %q", fragment)
		}
	}
}

func TestPassiveDiscoveryLatestReadHasMatchingIndex(t *testing.T) {
	migration, err := os.ReadFile("../../migrations/postgres/098_discovery_latest_read.sql")
	if err != nil {
		t.Fatal(err)
	}
	statement := string(migration)
	for _, fragment := range []string{"device_key", "source_id", "origin", "observed_at DESC", "id DESC"} {
		if !strings.Contains(statement, fragment) {
			t.Fatalf("latest observation index omitted %q", fragment)
		}
	}
}

func TestDeviceCacheReusesOneSnapshotAcrossCategoryQueries(t *testing.T) {
	cache := NewDeviceCache(time.Minute)
	loads := 0
	load := func() ([]DeviceView, error) {
		loads++
		return []DeviceView{{ID: "phone", Category: "mobile"}}, nil
	}
	first, err := cache.load("passive:24h", load)
	if err != nil {
		t.Fatal(err)
	}
	first[0].Category = "changed-by-caller"
	second, err := cache.load("passive:24h", load)
	if err != nil {
		t.Fatal(err)
	}
	if loads != 1 || second[0].Category != "mobile" {
		t.Fatalf("cache did not preserve one immutable snapshot: loads=%d items=%+v", loads, second)
	}
}

func TestAggregateDeviceRowsDescribesLinkLayerIdentity(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	row := deviceObservationRow{DeviceKey: "client", Observation: Observation{ID: "client", SourceID: "passive:office-30:ens1f1", Node: "office-30", Site: "office-30", Domain: "ens1f1", MAC: "00:11:22:33:44:66", Origin: "ieee1905_client", Confidence: "confirmed", ObservedAt: at, ValidUntil: at.Add(time.Hour)}}
	items := aggregateDeviceRows([]deviceObservationRow{row}, at.Add(time.Minute))
	if len(items) != 1 || items[0].PrimaryIP != "" || items[0].IdentityKind != "link_layer_association" || items[0].Category != "identity_only" {
		t.Fatalf("link-layer identity semantics are incomplete: %+v", items)
	}
}

func TestDeviceFacetsIncludeEmptyCategories(t *testing.T) {
	facets := deviceFacets([]DeviceView{{Category: "mobile"}, {Category: "identity_only"}})
	if len(facets) != 9 || facets[0].Category != "all" || facets[0].Count != 2 || facets[1].Count != 1 || facets[2].Count != 0 || facets[8].Count != 1 {
		t.Fatalf("unexpected facets: %+v", facets)
	}
}

func TestAggregateDeviceRowsMergesFriendlyMDNSInstances(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	withMAC := passiveRepositoryRow("mac-key", "192.168.0.64", "0e:df:fe:48:d4:08", "2a168803f56@刘璐的mac mini", "2a168803f56@刘璐的mac mini._raop._tcp.local", "", at)
	withoutMAC := passiveRepositoryRow("service-key", "fe80::107d:9f5:c216:aad3", "", "刘璐的mac mini", "刘璐的mac mini._airplay._tcp.local", "", at.Add(time.Second))
	items := aggregateDeviceRows([]deviceObservationRow{withMAC, withoutMAC}, at.Add(time.Minute))
	if len(items) != 1 || items[0].Name != "刘璐的mac mini" || len(items[0].Addresses) != 2 {
		t.Fatalf("friendly service identities were not merged: %+v", items)
	}
}

func TestAggregateDeviceRowsDoesNotMergeAmbiguousIPReuse(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	first := passiveRepositoryRow("first", "192.168.0.50", "00:11:22:33:44:50", "", "", "", at)
	second := passiveRepositoryRow("second", "192.168.0.50", "00:11:22:33:44:51", "", "", "", at.Add(time.Second))
	items := aggregateDeviceRows([]deviceObservationRow{first, second}, at.Add(time.Minute))
	if len(items) != 2 {
		t.Fatalf("conflicting MAC identities were merged: %+v", items)
	}
}

func TestAggregateDeviceRowsMergesCanonicalEndpointAndMatchingMAC(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	linked := passiveRepositoryRow("same-key", "10.0.0.8", "00:11:22:33:44:55", "AP", "", "", at)
	linked.EndpointID = "mac:00:11:22:33:44:55"
	unlinked := passiveRepositoryRow("same-key", "fe80::211:22ff:fe33:4455", "00:11:22:33:44:55", "AP", "", "", at.Add(time.Second))
	linked.Observation.ID = "linked-observation"
	unlinked.Observation.ID = "unlinked-observation"
	items := aggregateDeviceRows([]deviceObservationRow{linked, unlinked}, at.Add(time.Minute))
	if len(items) != 1 {
		t.Fatalf("same MAC was split by canonical endpoint linkage: %d groups", len(items))
	}
	if items[0].ID != "same-key" || items[0].EndpointID != linked.EndpointID || len(items[0].Addresses) != 2 || items[0].EvidenceCount != 2 {
		t.Fatalf("merge changed key or lost evidence: %+v", items[0])
	}
}

func TestAggregateDeviceRowsKeepsRealIdentityConflictSeparate(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	first := passiveRepositoryRow("same-key", "10.0.0.8", "00:11:22:33:44:55", "", "", "", at)
	first.EndpointID = "mac:00:11:22:33:44:55"
	for _, second := range []deviceObservationRow{
		passiveRepositoryRow("same-key", "10.0.0.8", "00:11:22:33:44:56", "", "", "", at.Add(time.Second)),
		{DeviceKey: "same-key", EndpointID: "registered-other", Observation: first.Observation},
		{DeviceKey: "same-key", EndpointID: "mac:00:11:22:33:44:56", Observation: first.Observation},
	} {
		items := aggregateDeviceRows([]deviceObservationRow{first, second}, at.Add(time.Minute))
		if len(items) != 2 {
			t.Fatalf("distinct identity was merged: endpoint=%s mac=%s", second.EndpointID, second.Observation.MAC)
		}
		for _, item := range items {
			if item.ID != "same-key" {
				t.Fatalf("split changed persisted device key: %s", item.ID)
			}
		}
	}
}

func TestAggregateDeviceRowsMergesCanonicalEndpointWithoutObservedMAC(t *testing.T) {
	at := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	mac := "00:11:22:33:44:55"
	linked := passiveRepositoryRow("service-key", "fe80::8", "", "printer", "", "", at)
	linked.EndpointID = "mac:" + mac
	observed := passiveRepositoryRow("mac-key", "10.0.0.8", mac, "printer", "", "", at.Add(time.Second))
	items := aggregateDeviceRows([]deviceObservationRow{linked, observed}, at.Add(time.Minute))
	if len(items) != 1 {
		t.Fatalf("canonical endpoint without observed MAC split from same MAC: %d groups", len(items))
	}
	if items[0].MAC != mac || items[0].EvidenceCount != 2 || len(items[0].Addresses) != 2 {
		t.Fatalf("lost observed identity or evidence: %+v", items[0])
	}
	for _, observation := range items[0].Observations {
		if observation.ID == linked.Observation.ID && observation.MAC != "" {
			t.Fatal("derived endpoint MAC rewrote raw observation")
		}
	}
}

func TestCanonicalEndpointWithoutMACPreservesScopeAndIdentityIsolation(t *testing.T) {
	at := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	observed := passiveRepositoryRow("mac-key", "10.0.0.8", "00:11:22:33:44:55", "", "", "", at)
	for _, tc := range []struct{ endpoint, vlan string }{{"mac:00:11:22:33:44:55", "20"}, {"registered:other", ""}, {"mac:00-11-22-33-44-55", ""}, {"mac:invalid", ""}} {
		linked := passiveRepositoryRow("service-key", "10.0.0.8", "", "", "", "", at)
		linked.EndpointID = tc.endpoint
		linked.Observation.VLAN = tc.vlan
		if items := aggregateDeviceRows([]deviceObservationRow{linked, observed}, at.Add(time.Minute)); len(items) != 2 {
			t.Fatalf("identity crossed boundary endpoint=%s vlan=%s", tc.endpoint, tc.vlan)
		}
	}
}

func TestCanonicalEndpointMACRequiresNormalizedUnicastAddress(t *testing.T) {
	for _, endpoint := range []string{"registered:x", "mac:invalid", "mac:00-11-22-33-44-55", "mac:01:11:22:33:44:55", "mac:00:00:00:00:00:00", "mac:00:11:22:33:44:55:66:77"} {
		if got := canonicalEndpointMAC(endpoint); got != "" {
			t.Fatalf("invalid canonical endpoint %s became %s", endpoint, got)
		}
	}
	if got := canonicalEndpointMAC("mac:00:11:22:33:44:aa"); got != "00:11:22:33:44:aa" {
		t.Fatalf("valid canonical endpoint=%s", got)
	}
}
