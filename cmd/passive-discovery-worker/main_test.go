package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

type rejectNetwork struct{ calls int }

func (r *rejectNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, errors.New("worker must remain offline")
}

func offlineWorkerTest(t *testing.T) {
	t.Helper()
	previous := fingerprint.Default()
	transport := http.DefaultTransport
	deny := &rejectNetwork{}
	http.DefaultTransport = deny
	t.Cleanup(func() {
		fingerprint.SetDefault(previous)
		http.DefaultTransport = transport
		if deny.calls != 0 {
			t.Errorf("worker made %d network requests", deny.calls)
		}
	})
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "false")
	t.Setenv("PROXY_SENTINEL_HARDWARE_SHADOW", "false")
}

func TestDefaultWorkerDoesNotReadFingerprintInstallation(t *testing.T) {
	offlineWorkerTest(t)
	t.Setenv("PROXY_SENTINEL_DEVICE_FINGERPRINT_DIR", "") // Explicit empty dir would fail if opened.
	before := fingerprint.Default()
	manager, err := openPassiveHardwareRuntime()
	if err != nil || manager != nil || fingerprint.Default() != before {
		t.Fatalf("184 default changed: manager=%v error=%v", manager, err)
	}
}

func TestHardwareWorkerRejectsMissingExplicitInstalledBundle(t *testing.T) {
	for _, gate := range []string{"PROXY_SENTINEL_HARDWARE_V2", "PROXY_SENTINEL_HARDWARE_SHADOW"} {
		t.Run(gate, func(t *testing.T) {
			offlineWorkerTest(t)
			t.Setenv(gate, "true")
			t.Setenv("PROXY_SENTINEL_DEVICE_FINGERPRINT_DIR", t.TempDir())
			if manager, err := openPassiveHardwareRuntime(); err == nil || manager != nil {
				t.Fatalf("missing installation silently accepted: %v %v", manager, err)
			}
		})
	}
}

func TestHardwareWorkerReloadsVerifiedOfflineV8AndRejectsV7(t *testing.T) {
	offlineWorkerTest(t)
	dir := t.TempDir()
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	v6, v7, v8 := filepath.Join(dir, "v6.tar.gz"), filepath.Join(dir, "v7.tar.gz"), filepath.Join(dir, "v8.tar.gz")
	if _, err := fingerprint.BuildEmbeddedBundle(v6, "worker-v6", now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(v6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fingerprint.BuildV7Bundle(raw, v7, "worker-v7", now); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(v7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fingerprint.BuildV8Bundle(raw, v8, "worker-v8", now); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(dir, "installed")
	m := fingerprint.NewManager(installed)
	if _, err = m.Import(raw); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROXY_SENTINEL_DEVICE_FINGERPRINT_DIR", installed)
	t.Setenv("PROXY_SENTINEL_HARDWARE_SHADOW", "true")
	if manager, err := openPassiveHardwareRuntime(); err == nil || manager != nil {
		t.Fatalf("V7 silently became hardware rules: %v %v", manager, err)
	}
	raw, err = os.ReadFile(v8)
	if err != nil {
		t.Fatal(err)
	}
	before := fingerprint.Default()
	if _, err = m.Import(raw); err != nil {
		t.Fatal(err)
	}
	// Reset the process default to prove startup reads and activates the local
	// installed release, rather than using the library the test importer set.
	fingerprint.SetDefault(before)
	manager, err := openPassiveHardwareRuntime()
	if err != nil || manager == nil {
		t.Fatalf("V8 startup: %v", err)
	}
	if status := manager.Status(); !status.OfflineMode || status.Version != "worker-v8" {
		t.Fatalf("wrong installed status: %+v", status)
	}
	probe := fingerprint.EvaluateHardware(fingerprint.HardwareInput{}, now)
	if probe.Incomplete || probe.SourceStatus != "verified_bundle" || probe.BundleVersion != "worker-v8" {
		t.Fatalf("installed runtime inactive: %+v", probe)
	}
	if err = os.WriteFile(filepath.Join(installed, "current", "hardware-catalog.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if manager, err := openPassiveHardwareRuntime(); err == nil || manager != nil {
		t.Fatalf("corrupt bundle silently accepted: %v %v", manager, err)
	}
}
