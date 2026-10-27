package fingerprint

import (
	"fmt"
	"strings"
	"time"
)

type bundleSignatureTables struct {
	snmp    *SNMPOIDTable
	prior   *VendorPriorTable
	model   *ModelCatalog
	service *ServiceTypeCatalog
}

var v7SignatureFiles = map[string][]byte{
	"snmp-enterprise-oid.json":  embeddedSNMPOIDs,
	"device-type-prior.json":    embeddedVendorPriors,
	"model-catalog.json":        embeddedModelCatalog,
	"service-type-catalog.json": embeddedServiceTypes,
}

func parseBundleSignatureTables(files map[string][]byte) (bundleSignatureTables, error) {
	var tables bundleSignatureTables
	var err error
	if tables.snmp, err = ParseSNMPOIDTable(files["snmp-enterprise-oid.json"]); err != nil {
		return tables, err
	}
	if tables.prior, err = ParseVendorPriorTable(files["device-type-prior.json"]); err != nil {
		return tables, err
	}
	if tables.model, err = ParseModelCatalog(files["model-catalog.json"]); err != nil {
		return tables, err
	}
	if tables.service, err = ParseServiceTypeCatalog(files["service-type-catalog.json"]); err != nil {
		return tables, err
	}
	for _, source := range []struct{ name, version, url, license string }{
		{"SNMP enterprise numbers", tables.snmp.Version, tables.snmp.SourceURL, tables.snmp.License},
		{"Device type priors", tables.prior.Version, tables.prior.SourceURL, tables.prior.License},
		{"Verified model catalog", tables.model.Version, tables.model.SourceURL, tables.model.License},
		{"Service type catalog", tables.service.Version, tables.service.SourceURL, tables.service.License},
	} {
		if strings.TrimSpace(source.version) == "" || strings.TrimSpace(source.url) == "" || strings.TrimSpace(source.license) == "" {
			return tables, fmt.Errorf("%s lacks source provenance", source.name)
		}
	}
	return tables, nil
}

func v7Sources(tables bundleSignatureTables) []BundleSource {
	return []BundleSource{
		{Name: "SNMP enterprise numbers", Version: tables.snmp.Version, URL: tables.snmp.SourceURL, License: tables.snmp.License},
		{Name: "Device type priors", Version: tables.prior.Version, URL: tables.prior.SourceURL, License: tables.prior.License},
		{Name: "Verified model catalog", Version: tables.model.Version, URL: tables.model.SourceURL, License: tables.model.License},
		{Name: "Service type catalog", Version: tables.service.Version, URL: tables.service.SourceURL, License: tables.service.License},
	}
}

func verifyV7Sources(manifest BundleManifest, tables bundleSignatureTables) error {
	for _, expected := range v7Sources(tables) {
		found := false
		for _, source := range manifest.Sources {
			if source.Name == expected.Name {
				if source != expected {
					return fmt.Errorf("source provenance differs from %s payload", expected.Name)
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing %s source provenance", expected.Name)
		}
	}
	return nil
}

func signatureTablesForBundle(bundle Bundle) (bundleSignatureTables, error) {
	if bundle.Manifest.SchemaVersion == BundleSchemaVersionV7 {
		return parseBundleSignatureTables(bundle.Files)
	}
	return parseBundleSignatureTables(v7SignatureFiles)
}

func activateSignatureTables(tables bundleSignatureTables) {
	SetSNMPOIDTable(tables.snmp)
	SetVendorPriorTable(tables.prior)
	SetModelCatalog(tables.model)
	SetServiceTypeCatalog(tables.service)
}

func signatureTableCounts(tables bundleSignatureTables) map[string]int {
	return map[string]int{
		"snmp_enterprise": len(tables.snmp.Entries),
		"vendor_prior":    len(tables.prior.Entries),
		"model_catalog":   len(tables.model.Entries),
		"service_type":    len(tables.service.Entries),
	}
}

// BuildV7Bundle upgrades a verified v6 pack without changing its existing
// public source payloads. Signature tables become manifest-verified data.
func BuildV7Bundle(baseData []byte, output, version string, now time.Time) (BundleManifest, error) {
	base, err := VerifyBundleBytes(baseData)
	if err != nil {
		return BundleManifest{}, err
	}
	if base.Manifest.SchemaVersion != BundleSchemaVersionV6 || strings.TrimSpace(version) == "" || version == base.Manifest.Version {
		return BundleManifest{}, fmt.Errorf("v7 upgrade requires a verified v6 pack and a new version")
	}
	tables, err := parseBundleSignatureTables(v7SignatureFiles)
	if err != nil {
		return BundleManifest{}, err
	}
	delete(base.Files, "manifest.json")
	for name, value := range v7SignatureFiles {
		base.Files[name] = value
	}
	manifest := base.Manifest
	manifest.SchemaVersion = BundleSchemaVersionV7
	manifest.Version = version
	manifest.CreatedAt = now.UTC().Format(time.RFC3339Nano)
	manifest.Sources = append(manifest.Sources, v7Sources(tables)...)
	manifest.Files = make(map[string]BundleFile, len(base.Files))
	for name, value := range base.Files {
		manifest.Files[name] = bundleFile(value)
	}
	data, err := encodeBundle(manifest, base.Files)
	if err != nil {
		return BundleManifest{}, err
	}
	if _, err := VerifyBundleBytes(data); err != nil {
		return BundleManifest{}, err
	}
	if err := writeBundleAtomic(output, data); err != nil {
		return BundleManifest{}, err
	}
	return manifest, nil
}
