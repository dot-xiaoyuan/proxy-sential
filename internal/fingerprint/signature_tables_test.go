package fingerprint

import (
	"encoding/json"
	"os"
	"testing"
)

// Rule input routing, match competition and source tiers.

func TestRuleInputRoutingScopesMatches(t *testing.T) {
	rules := []byte(`[
		{"pattern":"\\bAX55\\b","input":"ssdp_model","brand":"TP-Link","model_replacement":"AX55","device_type":"router","confidence":0.9}
	]`)
	library := MustLoad("input-routing", []byte("Assignment,Organization Name\n000000,Test\n"), rules)

	viaSSDP := library.IdentifySignals(Signals{ProtocolFields: map[string][]string{"ssdp_model": {"Archer AX55"}}})
	if viaSSDP.Brand != "TP-Link" || viaSSDP.Source != "device_rule:ssdp_model" {
		t.Fatalf("ssdp_model rule must fire on its own field: %+v", viaSSDP)
	}
	viaHostname := library.IdentifySignals(Signals{Hostnames: []string{"Archer AX55"}})
	if viaHostname.Brand != "" {
		t.Fatalf("ssdp_model rule must not inspect hostnames: %+v", viaHostname)
	}
}

func TestRuleOrderDoesNotChangeOutcome(t *testing.T) {
	specific := `{"pattern":"\\bDS-2CD2143G0-I\\b","brand":"Hikvision","model_replacement":"DS-2CD2143G0-I","device_type":"camera","confidence":0.9}`
	broad := `{"pattern":"\\bDS-2CD[0-9A-Z-]+\\b","brand":"Hikvision","device_type":"camera","confidence":0.7}`
	oui := []byte("Assignment,Organization Name\n000000,Test\n")

	forward := MustLoad("order-a", oui, []byte("["+specific+","+broad+"]"))
	reverse := MustLoad("order-b", oui, []byte("["+broad+","+specific+"]"))

	signals := Signals{Hostnames: []string{"DS-2CD2143G0-I"}}
	a, b := forward.IdentifySignals(signals), reverse.IdentifySignals(signals)
	if a.Brand != b.Brand || a.Model != b.Model || a.DeviceType != b.DeviceType {
		t.Fatalf("rule order changed the result: %+v vs %+v", a, b)
	}
	if a.Model != "DS-2CD2143G0-I" {
		t.Fatalf("highest-confidence rule must win: %+v", a)
	}
}

func TestOUICannotConfirmBrandOrModel(t *testing.T) {
	library := MustLoad("oui-only", []byte("Assignment,Organization Name\n001122,Example Networks\n"), []byte(`[]`))
	result := library.Identify("00:11:22:33:44:55")
	if result.Vendor != "Example Networks" || result.VendorConfidence != .9 {
		t.Fatalf("OUI must still report the vendor: %+v", result)
	}
	if result.Brand != "" || result.Model != "" || result.DeviceType != "" {
		t.Fatalf("OUI alone must not confirm brand/model/type: %+v", result)
	}
}

func TestRuleConflictIsReportedNotApplied(t *testing.T) {
	rules := []byte(`[
		{"pattern":"alpha","brand":"Alpha","device_type":"router","confidence":0.9},
		{"pattern":"alpha","brand":"Beta","device_type":"switch","confidence":0.9}
	]`)
	library := MustLoad("conflict", []byte("Assignment,Organization Name\n000000,Test\n"), rules)
	result := library.IdentifySignals(Signals{Hostnames: []string{"alpha"}})
	if !result.Conflict {
		t.Fatalf("conflicting high-confidence rules must be flagged: %+v", result)
	}
	if result.Brand != "Alpha" {
		t.Fatalf("the winning rule must be kept: %+v", result)
	}
}

func TestSNMPOIDResolvesVendor(t *testing.T) {
	library := Default()
	result := library.IdentifySignals(Signals{ProtocolFields: map[string][]string{"snmp_sysoid": {"1.3.6.1.4.1.2011.2.23"}}})
	if result.Vendor == "" || result.VendorConfidence != SNMPVendorConfidence {
		t.Fatalf("sysObjectID must resolve a vendor: %+v", result)
	}
	if result.Brand != "" || result.Model != "" {
		t.Fatalf("sysObjectID must not confirm brand or model: %+v", result)
	}
}

func TestModelCatalogResolvesMarketingName(t *testing.T) {
	brand, model, deviceType, confidence, ok := LookupModel("ADY-AL00")
	if !ok || brand != "Huawei" || model != "Pura 70" || deviceType != "mobile" || confidence != .95 {
		t.Fatalf("unexpected model lookup: %q %q %q %v %v", brand, model, deviceType, confidence, ok)
	}
	if _, _, _, _, ok := LookupModel("SM-G991B/DS"); !ok {
		t.Fatal("prefix variant must resolve")
	}
	if _, _, _, _, ok := LookupModel("NOT-A-CODE"); ok {
		t.Fatal("unknown code must not resolve")
	}
}

func TestProtocolModelFieldsReachModelCatalog(t *testing.T) {
	library := Default()
	for _, field := range []string{"ssdp_model", "snmp_model", "dns_sd_model", "mdns_model"} {
		result := library.IdentifySignals(Signals{ProtocolFields: map[string][]string{field: {"ADY-AL00"}}})
		if result.Brand != "Huawei" || result.Model != "Pura 70" || result.DeviceType != "mobile" {
			t.Fatalf("%s did not resolve the model code: %+v", field, result)
		}
	}
	// A user agent still cannot confirm a physical model on its own.
	result := library.IdentifySignals(Signals{UserAgents: []string{"ADY-AL00"}})
	if result.Brand != "" || result.Model != "" {
		t.Fatalf("unverified user agent must not establish a model: %+v", result)
	}
}

func TestVendorPriorIsFallbackOnly(t *testing.T) {
	deviceType, confidence, ok := LookupVendorPrior("Hangzhou Hikvision Digital Technology Co., Ltd")
	if !ok || deviceType != "camera" || confidence > .80 {
		t.Fatalf("unexpected vendor prior: %q %v %v", deviceType, confidence, ok)
	}
	// A rule-derived type must never be replaced by the weaker prior.
	library := Default()
	result := library.IdentifySignals(Signals{MAC: "00:11:22:33:44:55", Hostnames: []string{"routers"}})
	if result.DeviceType == "camera" {
		t.Fatalf("prior must not override explicit evidence: %+v", result)
	}
}

// Coverage baseline over the anonymised campus label fixture.

type fixtureDevice struct {
	MAC        string `json:"mac"`
	Vendor     string `json:"vendor"`
	ClientType string `json:"client_type"`
	Hostname   string `json:"hostname"`
	Model      string `json:"model"`
}

type deviceFixture struct {
	Source  string          `json:"source"`
	Devices []fixtureDevice `json:"devices"`
}

func loadDeviceFixture(t *testing.T) deviceFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/device-label-fixture.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture deviceFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fixture.Devices) != 42 {
		t.Fatalf("fixture must keep 42 devices, got %d", len(fixture.Devices))
	}
	return fixture
}

type deviceSnapshot struct {
	MAC    string `json:"mac"`
	Vendor string `json:"vendor"`
	Brand  string `json:"brand"`
	Model  string `json:"model"`
	Type   string `json:"device_type"`
}

// TestDeviceLabelFixtureSnapshot pins the recognition result for the anonymised
// campus fixture. It is a regression gate, not a coverage claim: the fixture is
// dominated by virtual machines and carries only two device-shaped hostnames.
// Regenerate testdata/device-label-baseline.json whenever a rule change is meant
// to alter these rows.
func TestDeviceLabelFixtureSnapshot(t *testing.T) {
	fixture := loadDeviceFixture(t)
	library := Default()
	got := make([]deviceSnapshot, 0, len(fixture.Devices))
	for _, device := range fixture.Devices {
		signals := Signals{MAC: device.MAC}
		if device.Hostname != "" {
			signals.Hostnames = []string{device.Hostname}
		}
		result := library.IdentifySignals(signals)
		got = append(got, deviceSnapshot{MAC: device.MAC, Vendor: result.Vendor, Brand: result.Brand, Model: result.Model, Type: result.DeviceType})
	}
	baseline, err := os.ReadFile("testdata/device-label-baseline.json")
	if err != nil {
		t.Fatalf("read baseline (regenerate with the documented helper): %v", err)
	}
	var want []deviceSnapshot
	if err := json.Unmarshal(baseline, &want); err != nil {
		t.Fatalf("decode baseline: %v", err)
	}
	if len(want) != len(got) {
		t.Fatalf("baseline has %d rows, fixture has %d", len(want), len(got))
	}
	for index := range want {
		if want[index] != got[index] {
			t.Fatalf("device %s changed: want %+v got %+v", want[index].MAC, want[index], got[index])
		}
	}
}
