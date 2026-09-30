package discovery

import (
	"encoding/json"
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
