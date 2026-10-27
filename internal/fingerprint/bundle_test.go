package fingerprint

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFingerbankLegacyConversionAndIdentification(t *testing.T) {
	raw := "[class 1]\ndescription=Windows\nmembers=100-199\n[os 100]\ndescription=Microsoft Windows 10\nvendor_id=<<EOT\nMSFT 5.0\nEOT\nfingerprints=<<EOT\n1,3,6,15,119,252\n1,3,6,15,119,251\n1,3,6,15,119,250\n1,3,6,15,119,249\n1,3,6,15,119,248\n1,3,6,15,119,247\n1,3,6,15,119,246\n1,3,6,15,119,245\n1,3,6,15,119,244\n1,3,6,15,119,243\nEOT\n"
	data, err := FingerbankFromLegacy([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	library, err := LoadWithData("test", embeddedOUI, []byte("[]"), data, embeddedBrandAliases)
	if err != nil {
		t.Fatal(err)
	}
	result := library.IdentifySignals(Signals{MAC: "e6:c4:00:00:00:01", DHCPVendorClass: "MSFT 5.0", DHCPRequestedOptions: "1, 3, 6, 15, 119, 252"})
	if result.OSFamily != "Windows" || result.DeviceType != "desktop" || result.Source != "fingerbank_dhcp" || result.Confidence < 0.9 {
		t.Fatalf("unexpected DHCP recognition: %+v", result)
	}
}

func TestBundleVerifyInstallAndChecksumFailure(t *testing.T) {
	previous := Default()
	defer SetDefault(previous)
	data := testBundleBytes(t)
	bundle, err := VerifyBundleBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(t.TempDir())
	manager.SetOffline(true)
	status, err := manager.Import(data)
	if err != nil {
		t.Fatal(err)
	}
	if status.Version != bundle.Manifest.Version || status.Source != "offline-bundle" || status.OUICount == 0 {
		t.Fatalf("unexpected status: %+v", status)
	}
	reloaded := NewManager(manager.dir).Status()
	if reloaded.DHCPRuleCount != status.DHCPRuleCount {
		t.Fatalf("rule count changed after reload: before=%d after=%d", status.DHCPRuleCount, reloaded.DHCPRuleCount)
	}
	corrupt := append([]byte{}, data...)
	corrupt[len(corrupt)/2] ^= 0xff
	if _, err := VerifyBundleBytes(corrupt); err == nil {
		t.Fatal("expected corrupt bundle rejection")
	}
	lastGoodVersion := Default().Version()
	if _, err := manager.Import(corrupt); err == nil || Default().Version() != lastGoodVersion {
		t.Fatalf("invalid import replaced the last good library: version=%s err=%v", Default().Version(), err)
	}
}

func TestOfflineBundleKeepsCurrentAndTwoPreviousVersionsAndSupportsRollback(t *testing.T) {
	previous := Default()
	defer SetDefault(previous)
	dir := t.TempDir()
	manager := NewManager(dir)
	manager.SetOffline(true)
	for _, version := range []string{"offline-retention-v1", "offline-retention-v2", "offline-retention-v3", "offline-retention-v4"} {
		if _, err := manager.Import(testBundleBytesVersion(t, version)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "releases"))
	if err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			kept++
		}
	}
	if kept != 3 {
		t.Fatalf("expected current and two previous releases, got %d", kept)
	}
	status, err := manager.Import(testBundleBytesVersion(t, "offline-retention-v2"))
	if err != nil || status.Version != "offline-retention-v2" || Default().Version() != "offline-retention-v2" {
		t.Fatalf("rollback bundle was not activated: status=%+v err=%v", status, err)
	}
}

func TestBundleRejectsPathTraversal(t *testing.T) {
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	payload := []byte("bad")
	_ = tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o600, Size: int64(len(payload))})
	_, _ = tw.Write(payload)
	_ = tw.Close()
	_ = gz.Close()
	if _, err := VerifyBundleBytes(output.Bytes()); err == nil {
		t.Fatal("expected path traversal rejection")
	}
}

func TestBundleRejectsNormalizedAndDuplicatePaths(t *testing.T) {
	for _, names := range [][]string{{"licenses/../oui.csv"}, {"oui.csv", "oui.csv"}} {
		var output bytes.Buffer
		gz := gzip.NewWriter(&output)
		tw := tar.NewWriter(gz)
		for _, name := range names {
			payload := []byte("bad")
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(payload))})
			_, _ = tw.Write(payload)
		}
		_ = tw.Close()
		_ = gz.Close()
		if _, err := VerifyBundleBytes(output.Bytes()); err == nil {
			t.Fatalf("expected unsafe names to be rejected: %v", names)
		}
	}
}

func TestBuildOfflineBundlePinsSources(t *testing.T) {
	badHaGeZi := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/hagezi-commit":
			fmt.Fprint(w, `{"sha":"aabbccddeeff0011"}`)
		case strings.HasPrefix(r.URL.Path, "/hagezi-raw/"):
			if badHaGeZi {
				fmt.Fprint(w, "# empty upstream list\n")
				return
			}
			if strings.HasSuffix(r.URL.Path, "/LICENSE") {
				fmt.Fprint(w, "GNU GENERAL PUBLIC LICENSE Version 3")
			} else {
				fmt.Fprintf(w, "telemetry.%s.test\n", strings.ReplaceAll(filepath.Base(r.URL.Path), "-", "."))
			}
		case r.URL.Path == "/commit":
			fmt.Fprint(w, `{"sha":"1234567890abcdef"}`)
		case r.URL.Path == "/next-commit":
			fmt.Fprint(w, `{"sha":"abcdef1234567890"}`)
		case strings.HasPrefix(r.URL.Path, "/next-raw/") && strings.HasSuffix(r.URL.Path, "/LICENSE"):
			fmt.Fprint(w, "MIT License\nCopyright (c) 2022 NextDNS\n")
		case strings.HasPrefix(r.URL.Path, "/next-raw/"):
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			fmt.Fprintf(w, "telemetry.%s.example.test\n", parts[len(parts)-1])
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			fmt.Fprint(w, "device_parsers:\n")
			for i := 0; i < 12; i++ {
				fmt.Fprintf(w, "  - regex: 'Device%d'\n    device_replacement: 'Model%d'\n", i, i)
			}
		case strings.HasPrefix(r.URL.Path, "/oui"):
			fmt.Fprint(w, "Registry,Assignment,Organization Name\nMA-L,000C29,VMware Inc.\n")
		case r.URL.Path == "/fingerbank":
			fmt.Fprint(w, "[class 1]\ndescription=Windows\nmembers=100-199\n[os 100]\ndescription=Windows\nfingerprints=<<EOT\n")
			for i := 0; i < 12; i++ {
				fmt.Fprintf(w, "1,3,6,15,%d\n", i)
			}
			fmt.Fprint(w, "EOT\n")
		case strings.Contains(r.URL.Path, "odbl"):
			fmt.Fprint(w, "Open Data Commons Open Database License ODbL")
		case strings.Contains(r.URL.Path, "dbcl"):
			fmt.Fprint(w, "Open Data Commons Database Contents License DbCL")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	options := BuildOptions{OUIURLs: []string{server.URL + "/oui-l", server.URL + "/oui-m", server.URL + "/oui-s"}, UAPCommitURL: server.URL + "/commit", UAPRawURL: server.URL + "/raw/%s", FingerbankURL: server.URL + "/fingerbank", ODbLURL: server.URL + "/license/odbl", DbCLURL: server.URL + "/license/dbcl", HaGeZiCommitURL: server.URL + "/hagezi-commit", HaGeZiRawURL: server.URL + "/hagezi-raw/%s/%s", NextDNSCommitURL: server.URL + "/next-commit", NextDNSRawURL: server.URL + "/next-raw/%s/%s", Now: func() time.Time { return time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC) }}
	manifest, err := BuildOfflineBundle(context.Background(), path, options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(manifest.Version, "1234567890ab") {
		t.Fatalf("version is not pinned: %s", manifest.Version)
	}
	if manifest.SchemaVersion != BundleSchemaVersionV6 || manifest.Sources[3].Version != "abcdef1234567890" {
		t.Fatalf("NextDNS source is not pinned in v6 manifest: %+v", manifest)
	}
	bundle, err := VerifyBundleFile(path)
	if err != nil || len(bundle.Files["domain-signatures.json"]) == 0 || len(bundle.Files["licenses/NextDNS-MIT.txt"]) == 0 || len(bundle.Files["application-signatures.json"]) == 0 {
		t.Fatalf("v5 bundle verification failed: files=%v err=%v", bundle.Files, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	badHaGeZi = true
	if _, err := BuildOfflineBundle(context.Background(), path, options); err == nil {
		t.Fatal("empty upstream replaced valid bundle")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed refresh changed output")
	}

}

func testBundleBytes(t *testing.T) []byte {
	return testBundleBytesVersion(t, "offline-test")
}

func testBundleBytesVersion(t *testing.T, version string) []byte {
	t.Helper()
	files := map[string][]byte{"oui.csv": embeddedOUI, "device-rules.json": embeddedRules, "fingerbank-dhcp.json": []byte(`[{"requested_options":"1,3,6","device_type":"desktop","os_family":"Windows","description":"test","confidence":0.84}]`), "brand-aliases.json": embeddedBrandAliases, "licenses/ODbL-1.0.html": []byte("ODbL"), "licenses/DbCL-1.0.html": []byte("DbCL"), "licenses/NOTICE.txt": []byte("Fingerbank data: ODbL and DbCL")}
	manifest := BundleManifest{SchemaVersion: BundleSchemaVersionV1, Version: version, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Sources: []BundleSource{{Name: "IEEE MA-L/MA-M/MA-S", Version: "1", URL: "https://example.test/ieee", License: "IEEE public registry"}, {Name: "uap-core", Version: "abc123", URL: "https://example.test/uap", License: "Apache-2.0"}, {Name: "Fingerbank public snapshot", Version: "1", URL: "https://example.test/fingerbank", License: "ODbL-1.0/DbCL-1.0"}}, Files: map[string]BundleFile{}}
	for name, data := range files {
		manifest.Files[name] = bundleFile(data)
	}
	encoded, err := encodeBundle(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestV6BuilderPreservesLegacyBundleReaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if _, err := BuildEmbeddedBundle(path, "compatibility", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	bundle, err := VerifyBundleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{BundleSchemaVersionV1, BundleSchemaVersionV2, BundleSchemaVersionV3, BundleSchemaVersionV4, BundleSchemaVersionV5} {
		names := []string{"oui.csv", "device-rules.json", "fingerbank-dhcp.json", "brand-aliases.json", "licenses/ODbL-1.0.html", "licenses/DbCL-1.0.html", "licenses/NOTICE.txt"}
		if version != BundleSchemaVersionV1 {
			names = append(names, "domain-signatures.json")
		}
		if version == BundleSchemaVersionV3 || version == BundleSchemaVersionV4 || version == BundleSchemaVersionV5 {
			names = append(names, "application-signatures.json")
		}
		if version == BundleSchemaVersionV5 {
			names = append(names, "router-rules.json")
		}
		manifest := bundle.Manifest
		manifest.SchemaVersion = version
		manifest.Files = map[string]BundleFile{}
		files := map[string][]byte{}
		for _, name := range names {
			files[name] = bundle.Files[name]
		}
		if version == BundleSchemaVersionV2 || version == BundleSchemaVersionV3 {
			files["licenses/NextDNS-MIT.txt"] = []byte("MIT License NextDNS")
			files["licenses/NOTICE.txt"] = append(append([]byte{}, files["licenses/NOTICE.txt"]...), []byte(" NextDNS MIT")...)
			manifest.Sources = append(append([]BundleSource{}, manifest.Sources...), BundleSource{Name: "NextDNS native-tracking-domains", Version: "test", URL: "https://example.test", License: "MIT"})
		}
		for name, data := range files {
			manifest.Files[name] = bundleFile(data)
		}
		data, err := encodeBundle(manifest, files)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = VerifyBundleBytes(data); err != nil {
			t.Fatalf("%s: %v", version, err)
		}
	}
}

// The v7 signature tables stay out of the bundle payload until a schema bump
// adds both their manifest checksums and a loader. A v6 bundle that smuggles one
// in must be rejected instead of being accepted and silently ignored.
func TestV6BundleRejectsSignatureTablePayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if _, err := BuildEmbeddedBundle(path, "signature-payload", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	bundle, err := VerifyBundleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"snmp-enterprise-oid.json", "device-type-prior.json", "model-catalog.json"} {
		files := make(map[string][]byte, len(bundle.Files))
		for existing, data := range bundle.Files {
			files[existing] = data
		}
		files[name] = []byte(`{}`)
		data, err := encodeBundle(bundle.Manifest, files)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyBundleBytes(data); err == nil || !strings.Contains(err.Error(), "unsupported entry") {
			t.Fatalf("%s must be rejected as an unsupported v6 entry, got %v", name, err)
		}
	}
}

func TestExtendKeepsLegacyPayloadAndRejectsBadBase(t *testing.T) {
	base := testBundleBytes(t)
	old, err := VerifyBundleBytes(base)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "v6.tar.gz")
	if _, err = ExtendOfflineBundle(base, output, "extended", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	next, err := VerifyBundleFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"oui.csv", "device-rules.json", "fingerbank-dhcp.json", "brand-aliases.json"} {
		if !bytes.Equal(old.Files[name], next.Files[name]) {
			t.Fatalf("legacy input replaced: %s", name)
		}
	}
	if _, err = ExtendOfflineBundle([]byte("corrupt"), output, "invalid", time.Now()); err == nil {
		t.Fatal("invalid base accepted")
	}
	if after, err := VerifyBundleFile(output); err != nil || after.Manifest.Version != "extended" {
		t.Fatal("failed extension changed valid bundle", err)
	}
}

func TestRefreshOfflineBundleRestoresVerifiedOUIAndKeepsOtherSources(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "base.tar.gz")
	if _, err := BuildEmbeddedBundle(basePath, "base", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	base, err := VerifyBundleBytes(baseData)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := VerifyBundleBytes(baseData)
	if err != nil {
		t.Fatal(err)
	}
	// The real failure was an embedded 11-row OUI replacing a much larger
	// previously verified IEEE registry while the other source files survived.
	var oui strings.Builder
	oui.WriteString("Assignment,Organization Name\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&oui, "%06X,Test Vendor %d\n", i*4, i)
	}
	prior.Files["oui.csv"] = []byte(oui.String())
	prior.Manifest.Files["oui.csv"] = bundleFile(prior.Files["oui.csv"])
	for i := range prior.Manifest.Sources {
		if prior.Manifest.Sources[i].Name == "IEEE MA-L/MA-M/MA-S" {
			prior.Manifest.Sources[i].Version = "verified-ieee-snapshot"
		}
	}
	priorData, err := encodeBundle(prior.Manifest, prior.Files)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "refresh.tar.gz")
	if _, err := RefreshOfflineBundle(baseData, priorData, output, "refreshed", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyBundleFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Files["oui.csv"], prior.Files["oui.csv"]) {
		t.Fatal("verified IEEE OUI was not restored")
	}
	for _, name := range []string{"multisource-catalog.json", "multisource-provenance.json", "fingerbank-dhcp.json", "domain-signatures.json", "brand-aliases.json"} {
		if !bytes.Equal(got.Files[name], base.Files[name]) {
			t.Fatalf("existing source was changed: %s", name)
		}
	}
	if got.Manifest.Sources[0].Version != "verified-ieee-snapshot" {
		t.Fatalf("OUI source provenance was not carried forward: %+v", got.Manifest.Sources[0])
	}
	if _, err := RefreshOfflineBundle(priorData, baseData, filepath.Join(t.TempDir(), "shrunk.tar.gz"), "shrunk", time.Unix(1, 0)); err == nil || !strings.Contains(err.Error(), "fewer OUI assignments") {
		t.Fatalf("a smaller IEEE source must be rejected: %v", err)
	}
	var rules []Rule
	if err := json.Unmarshal(got.Files["device-rules.json"], &rules); err != nil || len(rules) < len(mustEmbeddedRulesForTest(t)) {
		t.Fatalf("refreshed device rules invalid: count=%d err=%v", len(rules), err)
	}
}

func TestImportRejectsAccidentalLargeOUIShrink(t *testing.T) {
	previous := Default()
	defer SetDefault(previous)
	path := filepath.Join(t.TempDir(), "embedded.tar.gz")
	if _, err := BuildEmbeddedBundle(path, "small", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	smallData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	full, err := VerifyBundleBytes(smallData)
	if err != nil {
		t.Fatal(err)
	}
	var oui strings.Builder
	oui.WriteString("Assignment,Organization Name\n")
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&oui, "%06X,Test Vendor %d\n", i*4, i)
	}
	full.Files["oui.csv"] = []byte(oui.String())
	full.Manifest.Files["oui.csv"] = bundleFile(full.Files["oui.csv"])
	full.Manifest.Version = "full"
	fullData, err := encodeBundle(full.Manifest, full.Files)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(t.TempDir())
	if _, err := manager.Import(fullData); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Import(smallData); err == nil || !strings.Contains(err.Error(), "OUI") {
		t.Fatalf("smaller bootstrap library must be rejected: %v", err)
	}
	if manager.Status().Version != "full" || Default().Version() != "full" {
		t.Fatal("rejected import replaced the full library")
	}
}

func mustEmbeddedRulesForTest(t *testing.T) []Rule {
	t.Helper()
	var rules []Rule
	if err := json.Unmarshal(embeddedRules, &rules); err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestV7BundleCarriesVerifiedSignatureTablesAndReadsV6(t *testing.T) {
	legacyPath := filepath.Join(t.TempDir(), "legacy-v6.tar.gz")
	if _, err := BuildEmbeddedBundle(legacyPath, "legacy-v6", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundleBytes(legacy); err != nil {
		t.Fatalf("v6 reader compatibility: %v", err)
	}
	path := filepath.Join(t.TempDir(), "v7.tar.gz")
	if _, err := BuildV7Bundle(legacy, path, "layered-v7", time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	bundle, err := VerifyBundleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.SchemaVersion != BundleSchemaVersionV7 {
		t.Fatalf("wrong schema: %s", bundle.Manifest.SchemaVersion)
	}
	for _, name := range []string{"snmp-enterprise-oid.json", "device-type-prior.json", "model-catalog.json", "service-type-catalog.json"} {
		if len(bundle.Files[name]) == 0 || bundle.Manifest.Files[name] != bundleFile(bundle.Files[name]) {
			t.Fatalf("unverified signature payload %s", name)
		}
	}
	if !bytes.Equal(bundle.Files["oui.csv"], mustVerifyBundleBytesForTest(t, legacy).Files["oui.csv"]) {
		t.Fatal("v7 conversion replaced the existing IEEE source")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		SetDefault(mustLoadEmbedded())
		activateSignatureTables(mustParseEmbeddedSignatureTables())
	}()
	manager := NewManager(t.TempDir())
	status, err := manager.Import(data)
	if err != nil || status.Version != "layered-v7" {
		t.Fatalf("v7 import failed: status=%+v err=%v", status, err)
	}
	reloaded := NewManager(manager.dir)
	if reloaded.Status().Version != "layered-v7" {
		t.Fatalf("v7 restart lost active pack: %+v", reloaded.Status())
	}
}

func mustParseEmbeddedSignatureTables() bundleSignatureTables {
	tables, err := parseBundleSignatureTables(v7SignatureFiles)
	if err != nil {
		panic(err)
	}
	return tables
}

func mustVerifyBundleBytesForTest(t *testing.T, data []byte) Bundle {
	t.Helper()
	bundle, err := VerifyBundleBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}
