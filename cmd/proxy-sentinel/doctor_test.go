package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPercentileMs(t *testing.T) {
	values := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	if got := percentileMs(values, 50); got != 50 {
		t.Fatalf("p50 = %.1f, want 50", got)
	}
	if got := percentileMs(values, 95); got != 100 {
		t.Fatalf("p95 = %.1f, want 100", got)
	}
	if got := percentileMs(nil, 95); got != 0 {
		t.Fatalf("empty p95 = %.1f, want 0", got)
	}
}

func TestExecuteDoctorHealthyPassWithAuth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxy_sentinel_passive_health_available 1\n"))
	})
	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "ps_session", Value: "ok", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user":{"id":"admin"}}`))
	})
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("ps_session"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	snap := map[string]any{
		"sampled_at":   time.Now().UTC().Add(-60 * time.Second).Format(time.RFC3339),
		"release":      "2026.11.26-test",
		"alerts":       []string{},
		"errors":       map[string]string{},
		"failed_units": []string{},
		"timers": []map[string]any{
			{"unit": "proxy-sentinel-zeek-log-prune.timer", "active": true},
			{"unit": "proxy-sentinel-passive-health.timer", "active": true},
		},
		"disk": map[string]any{"available": 1_000_000_000_000, "total": 1_800_000_000_000},
		"watermarks": []map[string]any{
			{"sensor_id": "campus-204", "source_event_type": "capwap", "lag_seconds": 120},
		},
	}
	raw, _ := json.Marshal(snap)
	healthPath := filepath.Join(t.TempDir(), "latest.json")
	if err := os.WriteFile(healthPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	report := executeDoctor(doctorOptions{
		Addr:           srv.URL,
		HealthFile:     healthPath,
		Samples:        5,
		P95LimitMs:     500,
		P99LimitMs:     1000,
		MaxDiskUsedPct: 80,
		MaxLagSeconds:  900,
		AuthUser:       "admin",
		AuthPass:       "secret",
		Timeout:        5 * time.Second,
	})
	if report.OverallStatus != "PASS" {
		t.Fatalf("expected PASS, got %s: %+v", report.OverallStatus, report.Checks)
	}
	if len(report.LatencyProbes) != 5 {
		t.Fatalf("expected 5 latency probes (readyz + 4 auth endpoints), got %d", len(report.LatencyProbes))
	}
}

func TestExecuteDoctorFailsOnHighDiskAndLag(t *testing.T) {
	now := time.Now().UTC()
	snap := map[string]any{
		"sampled_at":   now.Format(time.RFC3339),
		"failed_units": []string{"proxy-sentinel-zeek.service"},
		"timers":       []map[string]any{{"unit": "proxy-sentinel-zeek-log-prune.timer", "active": false}},
		"disk":         map[string]any{"available": 50_000_000_000, "total": 1_000_000_000_000}, // 95% used
		"watermarks":   []map[string]any{{"sensor_id": "campus-204", "source_event_type": "dhcp", "lag_seconds": 1800}},
	}
	raw, _ := json.Marshal(snap)
	healthPath := filepath.Join(t.TempDir(), "latest.json")
	if err := os.WriteFile(healthPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	checks := checkPassiveHealthFile(healthPath, now, 80, 900)
	failed := map[string]bool{}
	for _, c := range checks {
		if c.Status == "FAIL" {
			failed[c.Name] = true
		}
	}
	for _, expected := range []string{"systemd_failed_units", "systemd_timers", "disk_capacity", "discovery_watermark_lag"} {
		if !failed[expected] {
			t.Fatalf("expected %s to FAIL, got %+v", expected, checks)
		}
	}
}
