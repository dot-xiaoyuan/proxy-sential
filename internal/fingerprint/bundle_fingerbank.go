package fingerprint

import (
	"fmt"
	"strings"
	"time"
)

// FingerbankBundleSourceName is the manifest entry the verifier requires for the
// Fingerbank DHCP payload. A refreshed snapshot keeps the same name so a bundle
// stays loadable by already deployed binaries; provenance moves in Version/URL.
const FingerbankBundleSourceName = "Fingerbank public snapshot"

// FingerbankReplaceOptions describes a snapshot refresh applied to a verified
// bundle. Every payload other than fingerbank-dhcp.json is copied byte-for-byte.
type FingerbankReplaceOptions struct {
	Output        string
	Version       string
	SourceVersion string
	SourceURL     string
	SourceLicense string
	Notice        []byte
	Now           time.Time
}

// ReplaceFingerbankSnapshot rebuilds a verified bundle with a new DHCP snapshot.
// It refuses to change the schema version: a refreshed snapshot must stay
// loadable by the deployed binary without an application release.
func ReplaceFingerbankSnapshot(baseData, fingerprintJSON []byte, options FingerbankReplaceOptions) (BundleManifest, error) {
	if strings.TrimSpace(options.Output) == "" {
		return BundleManifest{}, fmt.Errorf("output path is required")
	}
	if strings.TrimSpace(options.Version) == "" {
		return BundleManifest{}, fmt.Errorf("new bundle version is required")
	}
	if len(fingerprintJSON) == 0 {
		return BundleManifest{}, fmt.Errorf("fingerbank snapshot payload is empty")
	}
	base, err := VerifyBundleBytes(baseData)
	if err != nil {
		return BundleManifest{}, err
	}
	if base.Manifest.SchemaVersion != BundleSchemaVersionV6 && base.Manifest.SchemaVersion != BundleSchemaVersionV7 {
		return BundleManifest{}, fmt.Errorf("unsupported base bundle schema %q", base.Manifest.SchemaVersion)
	}
	delete(base.Files, "manifest.json")
	base.Files["fingerbank-dhcp.json"] = fingerprintJSON
	if len(options.Notice) > 0 {
		base.Files["licenses/NOTICE.txt"] = options.Notice
	}
	source := BundleSource{
		Name:    FingerbankBundleSourceName,
		Version: strings.TrimSpace(options.SourceVersion),
		URL:     strings.TrimSpace(options.SourceURL),
		License: strings.TrimSpace(options.SourceLicense),
	}
	if source.Version == "" || source.URL == "" || source.License == "" {
		return BundleManifest{}, fmt.Errorf("fingerbank source version, URL and license are required")
	}
	if !strings.Contains(source.License, "ODbL") {
		return BundleManifest{}, fmt.Errorf("bundle verifier requires the fingerbank source license to keep ODbL attribution")
	}
	sources := make([]BundleSource, 0, len(base.Manifest.Sources))
	replaced := false
	for _, item := range base.Manifest.Sources {
		if item.Name == FingerbankBundleSourceName {
			sources = append(sources, source)
			replaced = true
			continue
		}
		sources = append(sources, item)
	}
	if !replaced {
		sources = append(sources, source)
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	manifest := BundleManifest{
		SchemaVersion: base.Manifest.SchemaVersion,
		Version:       options.Version,
		CreatedAt:     now.UTC().Format(time.RFC3339Nano),
		Sources:       sources,
		Files:         map[string]BundleFile{},
	}
	for name, data := range base.Files {
		manifest.Files[name] = bundleFile(data)
	}
	encoded, err := encodeBundle(manifest, base.Files)
	if err != nil {
		return BundleManifest{}, err
	}
	if _, err = VerifyBundleBytes(encoded); err != nil {
		return BundleManifest{}, fmt.Errorf("rebuilt bundle failed verification: %w", err)
	}
	if err = writeBundleAtomic(options.Output, encoded); err != nil {
		return BundleManifest{}, err
	}
	return manifest, nil
}
