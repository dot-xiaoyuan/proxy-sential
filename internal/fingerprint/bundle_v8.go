package fingerprint

import (
	"fmt"
	"strings"
	"time"
)

var hardwareBundleSource = BundleSource{Name: "Proxy Sentinel hardware adjudication", Version: "hardware-catalog-2026-11-12.2", URL: "internal://proxy-sentinel/hardware-catalog", License: "internal-rule; upstream rules retain individual licenses"}
var nativeRecogSource = BundleSource{Name: "recog-go native matcher", Version: "v0.1.1-0.20230801014443-aa6fe9074750", URL: "https://github.com/runZeroInc/recog-go", License: "BSD-2-Clause"}

func verifyV8Hardware(manifest BundleManifest, files map[string][]byte) error {
	h, err := ParseHardwareCatalog(files["hardware-catalog.json"], files["multisource-provenance.json"], files["hardware-provenance.json"])
	if err != nil {
		return err
	}
	source := hardwareBundleSource
	source.Version = h.Version
	for _, expected := range []BundleSource{source, nativeRecogSource} {
		found := false
		for _, s := range manifest.Sources {
			if s == expected {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("missing V8 source provenance: %s", expected.Name)
		}
	}
	return nil
}

// BuildV8Bundle adds native hardware adjudication to a verified V7 pack.
// Existing V7 payload bytes are retained; the old recognition API is untouched.
func BuildV8Bundle(baseData []byte, output, version string, now time.Time) (BundleManifest, error) {
	base, err := VerifyBundleBytes(baseData)
	if err != nil {
		return BundleManifest{}, err
	}
	if base.Manifest.SchemaVersion != BundleSchemaVersionV7 || strings.TrimSpace(version) == "" || version == base.Manifest.Version {
		return BundleManifest{}, fmt.Errorf("v8 upgrade requires a verified v7 pack and a new version")
	}
	delete(base.Files, "manifest.json")
	base.Files["hardware-catalog.json"] = embeddedHardwareCatalog
	base.Files["hardware-provenance.json"] = embeddedHardwareProvenance
	manifest := base.Manifest
	manifest.SchemaVersion = BundleSchemaVersionV8
	manifest.Version = version
	manifest.CreatedAt = now.UTC().Format(time.RFC3339Nano)
	manifest.Sources = append(manifest.Sources, hardwareBundleSource, nativeRecogSource)
	manifest.Files = map[string]BundleFile{}
	for name, value := range base.Files {
		manifest.Files[name] = bundleFile(value)
	}
	data, err := encodeBundle(manifest, base.Files)
	if err != nil {
		return BundleManifest{}, err
	}
	if _, err = VerifyBundleBytes(data); err != nil {
		return BundleManifest{}, err
	}
	if err = writeBundleAtomic(output, data); err != nil {
		return BundleManifest{}, err
	}
	return manifest, nil
}
