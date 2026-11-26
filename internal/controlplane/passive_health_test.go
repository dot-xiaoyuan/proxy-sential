package controlplane

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadPassiveHealthSnapshotAndPrometheusMetrics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "latest.json")
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	missing := loadPassiveHealthSnapshot(path, now)
	if missing.Available {
		t.Fatalf("expected missing snapshot to report Available=false")
	}

	raw := `{
		"sampled_at": "2026-11-26T11:55:00+00:00",
		"release": "2026.11.26-12a9f70c",
		"alerts": ["archive_retry_exhausted"],
		"failed_units": [],
		"timers": [{"unit": "proxy-sentinel-zeek-log-prune.timer", "active": true}],
		"disk": {"available": 950000000000, "total": 1800000000000},
		"storage": {"postgres_bytes": 45000000000, "clickhouse_bytes": 520000000000, "zeek_logs_bytes": 12000000000},
		"archive_hardware": {"hardware_waiting": 12, "hardware_errors": 0, "waiting": 0, "retrying": 0, "failed": 120},
		"watermarks": [{"sensor_id": "campus-204", "source_event_type": "capwap", "cursor_timestamp": "2026-11-26T11:53:00+00:00", "updated_at": "2026-11-26T11:54:55+00:00"}]
	}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	snap := loadPassiveHealthSnapshot(path, now)
	if !snap.Available || snap.Stale || snap.AgeSeconds != 300 || snap.MaxWatermarkLagSeconds != 120 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if len(snap.Watermarks) != 1 || snap.Watermarks[0].LagSeconds != 120 {
		t.Fatalf("expected computed lag 120s, got %+v", snap.Watermarks)
	}

	t.Setenv("PROXY_SENTINEL_PASSIVE_HEALTH_FILE", path)
	rec := httptest.NewRecorder()
	(&Server{}).passiveHealthMetrics(rec)
	body := rec.Body.String()
	for _, want := range []string{
		"proxy_sentinel_passive_health_available 1",
		`proxy_sentinel_passive_health_storage_bytes{component="postgres"} 45000000000`,
		`proxy_sentinel_passive_health_storage_bytes{component="zeek"} 12000000000`,
		`proxy_sentinel_passive_health_source_lag_seconds{sensor_id="campus-204",source="capwap"} 120`,
		"proxy_sentinel_passive_health_archive_failed_rows 120",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, body)
		}
	}
}
