package fingerprint

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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

func TestBuildOfflineBundlePinsSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/commit":
			fmt.Fprint(w, `{"sha":"1234567890abcdef"}`)
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
		case strings.HasPrefix(r.URL.Path, "/license"):
			fmt.Fprint(w, "Open Data Commons license text")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	manifest, err := BuildOfflineBundle(context.Background(), path, BuildOptions{OUIURLs: []string{server.URL + "/oui-l", server.URL + "/oui-m", server.URL + "/oui-s"}, UAPCommitURL: server.URL + "/commit", UAPRawURL: server.URL + "/raw/%s", FingerbankURL: server.URL + "/fingerbank", ODbLURL: server.URL + "/license/odbl", DbCLURL: server.URL + "/license/dbcl", Now: func() time.Time { return time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(manifest.Version, "1234567890ab") {
		t.Fatalf("version is not pinned: %s", manifest.Version)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func testBundleBytes(t *testing.T) []byte {
	t.Helper()
	files := map[string][]byte{"oui.csv": embeddedOUI, "device-rules.json": embeddedRules, "fingerbank-dhcp.json": []byte(`[{"requested_options":"1,3,6","device_type":"desktop","os_family":"Windows","description":"test","confidence":0.84}]`), "brand-aliases.json": embeddedBrandAliases, "licenses/ODbL-1.0.html": []byte("ODbL"), "licenses/DbCL-1.0.html": []byte("DbCL"), "licenses/NOTICE.txt": []byte("notice")}
	manifest := BundleManifest{SchemaVersion: BundleSchemaVersion, Version: "offline-test", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Sources: []BundleSource{{Name: "test", Version: "1", URL: "https://example.test", License: "test"}}, Files: map[string]BundleFile{}}
	for name, data := range files {
		manifest.Files[name] = bundleFile(data)
	}
	encoded, err := encodeBundle(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
