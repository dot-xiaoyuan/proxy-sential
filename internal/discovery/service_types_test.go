package discovery

import (
	"encoding/json"
	"testing"
)

func TestServiceTypeCatalogCoversPrinterAndMedia(t *testing.T) {
	caps, ok := ServiceCapabilities("_ipp._tcp")
	if !ok || len(caps) != 1 || caps[0] != "printing" {
		t.Fatalf("_ipp._tcp must advertise printing: %v %v", caps, ok)
	}
	if kind, ok := ServiceProductKind("_googlecast._tcp"); !ok || kind != "media_player" {
		t.Fatalf("_googlecast._tcp must advertise media_player: %q %v", kind, ok)
	}
	if _, ok := ServiceCapabilities("_unknown-service._tcp"); ok {
		t.Fatal("unknown service must not resolve")
	}
}

func TestParseServiceTypeCatalogRejectsInvalid(t *testing.T) {
	if _, err := ParseServiceTypeCatalog([]byte(`{"version":"","source":"x","entries":{}}`)); err == nil {
		t.Fatal("empty version must be rejected")
	}
	if _, err := ParseServiceTypeCatalog([]byte(`{"version":"v1","source":"x","entries":{"ipp_tcp":{}}}`)); err == nil {
		t.Fatal("service names without a leading underscore must be rejected")
	}
	catalog, err := ParseServiceTypeCatalog(embeddedServiceTypes)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.SourceURL == "" || len(catalog.Entries) == 0 {
		t.Fatalf("service catalogue must carry provenance: %+v", catalog)
	}
}

func TestProductRulesAreDataDriven(t *testing.T) {
	if len(campusProductRules) != 8 {
		t.Fatalf("product rules must keep the migrated eight entries, got %d", len(campusProductRules))
	}
	specs := []struct {
		input string
		kind  string
		make  string
	}{
		{"DS-2CD2143G0-I", "camera", "Hikvision"},
		{"IPC-HDW5442T-ZE", "camera", "Dahua"},
		{"AppleTV6,2", "media_player", "Apple"},
		{"ZKTeco iClock880", "attendance", "ZKTeco"},
	}
	for _, spec := range specs {
		matched := false
		for _, rule := range campusProductRules {
			if rule.pattern.FindString(spec.input) != "" {
				if rule.kind != spec.kind || rule.manufacturer != spec.make {
					t.Fatalf("%s matched %s/%s, want %s/%s", spec.input, rule.kind, rule.manufacturer, spec.kind, spec.make)
				}
				matched = true
			}
		}
		if !matched {
			t.Fatalf("%s no longer matches any product rule", spec.input)
		}
	}
	var table productRuleTable
	if err := json.Unmarshal(embeddedProductRules, &table); err != nil {
		t.Fatalf("decode embedded product rules: %v", err)
	}
	if table.Version == "" || table.Source == "" || table.SourceURL == "" || table.License == "" {
		t.Fatalf("product rules must carry provenance: %+v", table)
	}
}
