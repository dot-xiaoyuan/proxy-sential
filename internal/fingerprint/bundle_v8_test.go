package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestV8BundlePreservesV7AndNativeSources(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	v6 := filepath.Join(dir, "v6.tar.gz")
	v7 := filepath.Join(dir, "v7.tar.gz")
	v8 := filepath.Join(dir, "v8.tar.gz")
	if _, err := BuildEmbeddedBundle(v6, "fixture-v6", now); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(v6)
	if _, err := BuildV7Bundle(b, v7, "fixture-v7", now); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(v7)
	legacyData := append([]byte(nil), b...)
	old, err := VerifyBundleBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BuildV8Bundle(b, v8, "fixture-v8", now); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(v8)
	pack, err := VerifyBundleBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if pack.Manifest.SchemaVersion != BundleSchemaVersionV8 {
		t.Fatal(pack.Manifest.SchemaVersion)
	}
	for name, value := range old.Files {
		if name == "manifest.json" {
			continue
		}
		if string(pack.Files[name]) != string(value) {
			t.Fatalf("legacy file changed: %s", name)
		}
	}
	if _, err := ParseHardwareCatalog(pack.Files["hardware-catalog.json"], pack.Files["multisource-provenance.json"], pack.Files["hardware-provenance.json"]); err != nil {
		t.Fatal(err)
	}
	previous := Default()
	defer func() { SetDefault(previous); activateSignatureTables(mustParseEmbeddedSignatureTables()) }()
	m := NewManager(filepath.Join(dir, "installed"))
	if _, err := m.Import(legacyData); err != nil {
		t.Fatal(err)
	}
	if probe := Default().EvaluateHardware(HardwareInput{}, now); probe.SourceStatus != "unavailable" || !probe.Incomplete || probe.BundleVersion != "fixture-v7" {
		t.Fatalf("installed V7 import fallback: %+v", probe)
	}
	_ = NewManager(m.dir)
	if probe := Default().EvaluateHardware(HardwareInput{}, now); probe.SourceStatus != "unavailable" || !probe.Incomplete || probe.BundleVersion != "fixture-v7" {
		t.Fatalf("installed V7 restart fallback: %+v", probe)
	}
	if _, err := m.Import(b); err != nil {
		t.Fatal(err)
	}
	if Default().hardware == nil {
		t.Fatal("V8 hardware catalog was not activated")
	}
	probe := Default().EvaluateHardware(HardwareInput{}, now)
	if probe.SourceStatus != "verified_bundle" || probe.BundleVersion != "fixture-v8" || probe.BundleSchema != BundleSchemaVersionV8 || probe.Version == "" {
		t.Fatalf("V8 source provenance: %+v", probe)
	}
	reloaded := NewManager(m.dir)
	if reloaded.Status().Status != "ready" || Default().hardware == nil {
		t.Fatalf("V8 reload: %+v", reloaded.Status())
	}
	pack.Files["hardware-catalog.json"] = []byte(`{}`)
	corrupt, _ := encodeBundle(pack.Manifest, pack.Files)
	if _, err := VerifyBundleBytes(corrupt); err == nil {
		t.Fatal("corrupt v8 accepted")
	}
}
