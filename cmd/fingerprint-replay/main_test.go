package main

import (
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/fingerprint"
)

func TestLoadLibraryIncludesInstalledMultisourceCatalog(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"oui.csv":                  "Assignment,Organization Name\n000000,Test Vendor\n",
		"device-rules.json":        "[]",
		"fingerbank-dhcp.json":     "[]",
		"brand-aliases.json":       "{}",
		"domain-signatures.json":   "[]",
		"multisource-catalog.json": `{"sources":[{"id":"site-catalog","url":"https://example.test/catalog","license":"MIT"}],"rules":[{"id":"printer-banner","source_id":"site-catalog","version":"1","status":"converted","strength":"self_report","conditions":[{"field":"http_server","operator":"exact","value":"SitePrinter/1"}],"role":"printer"}]}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, variant := range []struct {
		name     string
		override []byte
	}{
		{name: "baseline"},
		{name: "fingerbank replacement", override: []byte("[]")},
	} {
		t.Run(variant.name, func(t *testing.T) {
			library, err := loadLibrary(dir, "test", variant.override)
			if err != nil {
				t.Fatal(err)
			}
			got := library.IdentifySignals(fingerprint.Signals{ProtocolFields: map[string][]string{"http_server": {"SitePrinter/1"}}})
			if len(got.SourceMatches) != 1 || got.SourceMatches[0].SourceID != "site-catalog" || got.DeviceType != "printer" {
				t.Fatalf("installed multisource rule missing from %s: %+v", variant.name, got)
			}
		})
	}
}

func TestCompareReportsNewRecognitionWithoutLeakingInputs(t *testing.T) {
	oui := []byte("Assignment,Organization Name\nABCDEF,Example\n")
	base, err := fingerprint.LoadWithData("base", oui, []byte("[]"), []byte("[]"), []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := fingerprint.LoadWithData("updated", oui, []byte("[]"), []byte(`[{"requested_options":"1,3,6","vendor_classes":["MSFT"],"vendor_required":true,"device_type":"desktop","os_family":"Windows","confidence":0.88}]`), []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	inputs := []replayInput{
		{weight: 4, signals: fingerprint.Signals{DHCPRequestedOptions: "1,3,6", DHCPVendorClass: "MSFT", Hostnames: []string{"private-hostname"}}},
		{weight: 2, signals: fingerprint.Signals{DHCPRequestedOptions: "1,3,6", DHCPVendorClass: "OTHER"}},
	}
	comparison := compare(base, updated, inputs)
	if comparison["new_device_type"] != 4 || comparison["new_os_family"] != 4 || comparison["new_conflicts"] != 0 {
		t.Fatalf("comparison=%v", comparison)
	}
	residual := comparison["still_untyped_by_signal"].(map[string]int)
	if residual["dhcp_options"] != 2 {
		t.Fatalf("residual signal counts=%v", residual)
	}
	if _, ok := comparison["private-hostname"]; ok {
		t.Fatal("comparison must not contain endpoint attributes")
	}
}
