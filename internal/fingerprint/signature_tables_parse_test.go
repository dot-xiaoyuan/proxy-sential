package fingerprint

import "testing"

func TestParseSignatureTablesRejectInvalid(t *testing.T) {
	if _, err := ParseSNMPOIDTable([]byte(`{"version":"","source":"x","entries":{}}`)); err == nil {
		t.Fatal("empty version must be rejected")
	}
	if _, err := ParseSNMPOIDTable([]byte(`{"version":"v1","source":"x","entries":{}}`)); err == nil {
		t.Fatal("empty entry map must be rejected")
	}
	if _, err := ParseVendorPriorTable([]byte(`{"version":"v1","source":"x","entries":[{"vendor":"A","device_type":"camera","confidence":0.95}]}`)); err == nil {
		t.Fatal("prior confidence above 0.80 must be rejected")
	}
	if _, err := ParseModelCatalog([]byte(`{"version":"v1","source":"x","entries":{"AB":{"brand":"B","model":"M","confidence":0.9}}}`)); err == nil {
		t.Fatal("model codes shorter than five characters must be rejected")
	}
	if _, err := ParseModelCatalog([]byte(`{"version":"v1","source":"x","entries":{"ABCDE":{"brand":"B","model":"","confidence":0.9}}}`)); err == nil {
		t.Fatal("empty model name must be rejected")
	}
}

func TestSignatureTablesCarryProvenance(t *testing.T) {
	table, err := ParseSNMPOIDTable(embeddedSNMPOIDs)
	if err != nil {
		t.Fatal(err)
	}
	if table.Version == "" || table.Source == "" || table.SourceURL == "" || len(table.Entries) < 60000 {
		t.Fatalf("SNMP table must be complete and attributed: version=%q entries=%d", table.Version, len(table.Entries))
	}
	priors, err := ParseVendorPriorTable(embeddedVendorPriors)
	if err != nil {
		t.Fatal(err)
	}
	if priors.Source == "" || len(priors.Entries) == 0 {
		t.Fatalf("vendor prior table must be attributed: %+v", priors)
	}
	catalog, err := ParseModelCatalog(embeddedModelCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Source == "" || len(catalog.Entries) == 0 {
		t.Fatalf("model catalogue must be attributed: %+v", catalog)
	}
}
