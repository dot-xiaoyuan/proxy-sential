package controlplane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoveryQuarantineStatusDistinguishesClearAndBlocked(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "quarantine")
	if state := discoveryQuarantineStatus(dir); state.Status != "clear" {
		t.Fatalf("missing quarantine directory is not clear: %+v", state)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "segment.segment"), []byte("raw"), 0600); err != nil {
		t.Fatal(err)
	}
	if state := discoveryQuarantineStatus(dir); state.Status != "clear" {
		t.Fatalf("raw file alone became a false alert: %+v", state)
	}
	if err := os.WriteFile(filepath.Join(dir, "segment.json"), []byte(`{"status":"quarantined_unprocessed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if state := discoveryQuarantineStatus(dir); state.Status != "blocked" || state.CountAtLeast != 1 {
		t.Fatalf("quarantined segment was hidden: %+v", state)
	}
}
