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
	for _, field := range []string{"addresses", "capabilities", "protocols", "observations"} {
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
