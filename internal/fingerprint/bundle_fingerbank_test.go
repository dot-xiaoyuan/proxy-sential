package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func buildTestBundle(t *testing.T, dir string) ([]byte, Bundle) {
	t.Helper()
	path := filepath.Join(dir, "base.tar.gz")
	if _, err := BuildEmbeddedBundle(path, "embedded-test", time.Now()); err != nil {
		t.Fatalf("build embedded bundle: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	base, err := VerifyBundleBytes(data)
	if err != nil {
		t.Fatalf("verify base: %v", err)
	}
	return data, base
}

func TestReplaceFingerbankSnapshotKeepsEveryOtherPayload(t *testing.T) {
	dir := t.TempDir()
	baseData, base := buildTestBundle(t, dir)
	payload := []byte(`[{"requested_options":"1,3,6,15","device_type":"desktop","os_family":"Windows","description":"Windows OS","confidence":0.84}]`)
	output := filepath.Join(dir, "refreshed.tar.gz")
	manifest, err := ReplaceFingerbankSnapshot(baseData, payload, FingerbankReplaceOptions{
		Output:        output,
		Version:       "offline-test-fingerbank",
		SourceVersion: "2026-11-02",
		SourceURL:     "https://api.fingerbank.org/api/v2/download/db",
		SourceLicense: "ODbL-1.0/DbCL-1.0",
		Now:           time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	refreshed, err := VerifyBundleFile(output)
	if err != nil {
		t.Fatalf("verify refreshed: %v", err)
	}
	if refreshed.Manifest.Version != "offline-test-fingerbank" {
		t.Fatalf("version=%s", refreshed.Manifest.Version)
	}
	if refreshed.Manifest.SchemaVersion != base.Manifest.SchemaVersion {
		t.Fatalf("schema changed: %s -> %s", base.Manifest.SchemaVersion, refreshed.Manifest.SchemaVersion)
	}
	if string(refreshed.Files["fingerbank-dhcp.json"]) != string(payload) {
		t.Fatal("fingerbank payload was not replaced")
	}
	for name, data := range base.Files {
		if name == "manifest.json" || name == "fingerbank-dhcp.json" {
			continue
		}
		if string(refreshed.Files[name]) != string(data) {
			t.Fatalf("payload %s changed unexpectedly", name)
		}
	}
	var source BundleSource
	for _, item := range manifest.Sources {
		if item.Name == FingerbankBundleSourceName {
			source = item
		}
	}
	if source.Version != "2026-11-02" || source.URL == "" || source.License != "ODbL-1.0/DbCL-1.0" {
		t.Fatalf("fingerbank source not updated: %+v", source)
	}
	installDir := filepath.Join(dir, "install")
	status, err := NewManager(installDir).Import(mustRead(t, output))
	if err != nil {
		t.Fatalf("import refreshed bundle: %v", err)
	}
	if status.Status != "ready" || status.DHCPRuleCount != 1 {
		t.Fatalf("import status=%+v", status)
	}
}

func TestReplaceFingerbankSnapshotRejectsInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	baseData, _ := buildTestBundle(t, dir)
	valid := FingerbankReplaceOptions{
		Output:        filepath.Join(dir, "out.tar.gz"),
		Version:       "refreshed",
		SourceVersion: "2026-11-02",
		SourceURL:     "https://api.fingerbank.org/api/v2/download/db",
		SourceLicense: "ODbL-1.0/DbCL-1.0",
	}
	cases := map[string]struct {
		payload []byte
		options FingerbankReplaceOptions
	}{
		"empty payload":          {nil, valid},
		"missing output":         {[]byte("[]"), func() FingerbankReplaceOptions { o := valid; o.Output = ""; return o }()},
		"missing version":        {[]byte("[]"), func() FingerbankReplaceOptions { o := valid; o.Version = ""; return o }()},
		"license without odbl":   {[]byte("[]"), func() FingerbankReplaceOptions { o := valid; o.SourceLicense = "proprietary"; return o }()},
		"missing source version": {[]byte("[]"), func() FingerbankReplaceOptions { o := valid; o.SourceVersion = ""; return o }()},
	}
	for name, tc := range cases {
		if _, err := ReplaceFingerbankSnapshot(baseData, tc.payload, tc.options); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestReplaceFingerbankSnapshotRejectsCorruptBase(t *testing.T) {
	if _, err := ReplaceFingerbankSnapshot([]byte("not a bundle"), []byte("[]"), FingerbankReplaceOptions{
		Output: filepath.Join(t.TempDir(), "out.tar.gz"), Version: "v", SourceVersion: "s",
		SourceURL: "u", SourceLicense: "ODbL-1.0/DbCL-1.0",
	}); err == nil {
		t.Fatal("expected corrupt base bundle to fail")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
