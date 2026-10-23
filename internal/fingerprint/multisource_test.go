package fingerprint

import (
	"encoding/json"
	"testing"
)

func TestCatalogClassifiesAndMatchesDirectionalFields(t *testing.T) {
	c := Catalog{Sources: []FingerprintSource{{ID: "test", URL: "https://example.test", License: "BSD-2-Clause"}}, Rules: []SourceRule{
		{ID: "a", SourceID: "test", Version: "1", Status: "converted", Direction: "server", Conditions: []FingerprintCondition{{Field: "http_server", Operator: "regex", Value: "^Printer/"}}, Examples: []FingerprintExample{{Values: map[string]string{"http_server": "Printer/1"}, Match: true}}, Role: "printer"},
		{ID: "b", SourceID: "test", Version: "1", Status: "converted", Direction: "server", Conditions: []FingerprintCondition{{Field: "http_server", Operator: "regex", Value: "^Printer/"}}, Role: "printer"},
		{ID: "bad", SourceID: "test", Version: "1", Status: "converted", Conditions: []FingerprintCondition{{Field: "http_server", Operator: "regex", Value: "(?<=foo)bar"}}},
	}}
	PrepareCatalog(&c)
	if c.Rules[1].Status != "duplicate" || c.Rules[2].Status != "unsupported_syntax" {
		t.Fatalf("classification: %+v", c.Rules)
	}
	data, _ := json.Marshal(&c)
	loaded, err := LoadCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Match(map[string][]string{"hostname": {"Printer/1"}}); len(got) != 0 {
		t.Fatal("protocol input crossed")
	}
	if got := loaded.Match(map[string][]string{"http_server": {"Printer/1"}}); len(got) != 1 || got[0].SourceID != "test" {
		t.Fatalf("match: %+v", got)
	}
}
func TestCatalogRejectsEnabledUnsupportedExpression(t *testing.T) {
	_, err := LoadCatalog([]byte(`{"sources":[{"id":"s","url":"https://example.test","license":"MIT"}],"rules":[{"id":"a","source_id":"s","version":"1","status":"converted","conditions":[{"field":"http_server","operator":"regex","value":"(?=x)"}]}]}`))
	if err == nil {
		t.Fatal("invalid enabled regex accepted")
	}
}

func TestCatalogEmptyOIDAndCaptureReplay(t *testing.T) {
	c := Catalog{Sources: []FingerprintSource{{ID: "s", URL: "https://example.test", License: "MIT"}}, Rules: []SourceRule{
		{ID: "oid", SourceID: "s", Version: "1", Status: "converted", Conditions: []FingerprintCondition{{Field: "snmp_sysoid", Operator: "oid_prefix", Value: ".1.3.6.1.4.1.9"}}},
		{ID: "capture", SourceID: "s", Version: "1", Status: "converted", Model: "$1", Conditions: []FingerprintCondition{{Field: "http_server", Operator: "regex", Value: "^(.*)$"}}},
	}}
	PrepareCatalog(&c)
	data, _ := json.Marshal(&c)
	loaded, err := LoadCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Match(map[string][]string{"http_server": {""}, "snmp_sysoid": {".1.3.6.1.4.1.90"}}); len(got) != 0 {
		t.Fatalf("empty or adjacent OID matched: %+v", got)
	}
	got := loaded.Match(map[string][]string{"http_server": {"Printer-42"}, "snmp_sysoid": {"1.3.6.1.4.1.9.1"}})
	if len(got) != 2 || got[0].Model != "Printer-42" {
		t.Fatalf("capture/OID: %+v", got)
	}
}
func TestCatalogAuxiliaryAndConflictingRoles(t *testing.T) {
	var result Result
	applySourceMatches(&result, []SourceMatch{{SourceID: "tls", Role: "router", Strength: "auxiliary"}})
	if result.DeviceType != "" {
		t.Fatal("certificate confirmed router")
	}
	applySourceMatches(&result, []SourceMatch{{Role: "router", Strength: "self_report"}, {Role: "access_point", Strength: "self_report"}})
	if !result.Conflict || result.DeviceType != "" {
		t.Fatal("conflicting roles confirmed")
	}
}

func TestEmbeddedCatalogAccountingAndProvenance(t *testing.T) {
	if err := VerifyCatalogProvenance(embeddedCatalog, embeddedProvenance); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalog(embeddedCatalog)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, s := range c.Sources {
		n := 0
		for _, v := range s.Dispositions {
			n += v
		}
		if n != s.RawCount {
			t.Fatalf("%s unaccounted records", s.ID)
		}
		total += n
	}
	if total != len(c.Rules) {
		t.Fatal("unaccounted source")
	}
	var files map[string]string
	_ = json.Unmarshal(embeddedProvenance, &files)
	files["recog/LICENSE"] += "tampered"
	data, _ := json.Marshal(files)
	if VerifyCatalogProvenance(embeddedCatalog, data) == nil {
		t.Fatal("tampered source accepted")
	}
}

func TestEmbeddedCatalogUpstreamExamplesAndNoBrandOnlyRouter(t *testing.T) {
	c, err := LoadCatalog(embeddedCatalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Rules {
		if r.Status != "converted" {
			continue
		}
		for _, e := range r.Examples {
			values := map[string][]string{}
			for k, v := range e.Values {
				values[k] = []string{v}
			}
			if ruleMatches(r, values) != e.Match {
				t.Errorf("upstream example failed: %s", r.ID)
			}
		}
	}
	for _, signals := range []Signals{
		{Hostnames: []string{"TP-Link Archer T4U"}},
		{Hostnames: []string{"Archer TX20U Plus"}},
		{ProtocolFields: map[string][]string{"http_server": {"Linux"}}},
		{ProtocolFields: map[string][]string{"tls_subject": {"CN=*.tplinkcloud.com.cn"}}},
	} {
		var r Result
		applySourceMatches(&r, c.Match(catalogSignalValues(signals)))
		if r.DeviceType == "router" {
			t.Fatalf("auxiliary evidence promoted router: %+v", r)
		}
	}
}
func TestCatalogCacheIsolation(t *testing.T) {
	c, err := LoadCatalog(embeddedCatalog)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string][]string{"dhcp_vendor_class": {"MSFT 5.0"}}
	a := c.Match(values)
	if len(a) == 0 {
		t.Fatal("expected Windows replay match")
	}
	a[0].Name = "mutated"
	a[0].Fields[0] = "mutated"
	b := c.Match(values)
	if b[0].Name == "mutated" || b[0].Fields[0] == "mutated" {
		t.Fatal("cache exposed mutable data")
	}
}
