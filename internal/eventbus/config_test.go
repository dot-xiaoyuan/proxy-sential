package eventbus

import (
	"strings"
	"testing"
	"time"
)

func clearEventBusEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PROXY_SENTINEL_EVENT_BUS_SHADOW",
		"PROXY_SENTINEL_EVENT_BUS_BROKERS",
		"PROXY_SENTINEL_EVENT_BUS_CLIENT_ID",
		"PROXY_SENTINEL_EVENT_BUS_DISCOVERY_TOPIC",
		"PROXY_SENTINEL_EVENT_BUS_LINGER_MS",
		"PROXY_SENTINEL_EVENT_BUS_QUEUE",
		"PROXY_SENTINEL_EVENT_BUS_MAX_RECORD_BYTES",
		"PROXY_SENTINEL_EVENT_BUS_STATS_PATH",
	} {
		t.Setenv(key, "")
	}
}

func TestConfigDisabledDefaults(t *testing.T) {
	clearEventBusEnv(t)
	cfg, err := ConfigFromEnv("sensor-a", "/tmp/eventbus-stats")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("shadow must be disabled by default")
	}
	if cfg.ClientID != "discovery-sensor-a" {
		t.Fatalf("client id = %q", cfg.ClientID)
	}
	if cfg.DiscoveryTopic != DefaultDiscoveryTopic {
		t.Fatalf("topic = %q", cfg.DiscoveryTopic)
	}
	if cfg.Linger != 5*time.Millisecond {
		t.Fatalf("linger = %s", cfg.Linger)
	}
	if cfg.Queue != 8192 || cfg.MaxRecordBytes != 900<<10 {
		t.Fatalf("defaults = %+v", cfg)
	}
	if !strings.HasSuffix(cfg.StatsPath, "eventbus.stats") {
		t.Fatalf("stats path = %q", cfg.StatsPath)
	}
}

func TestConfigEnabledRequiresBrokers(t *testing.T) {
	clearEventBusEnv(t)
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_SHADOW", "true")
	if _, err := ConfigFromEnv("sensor-a", t.TempDir()); err == nil {
		t.Fatal("expected missing brokers error")
	}
}

func TestConfigEnabledParses(t *testing.T) {
	clearEventBusEnv(t)
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_SHADOW", "true")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_BROKERS", "127.0.0.1:19092, 127.0.0.1:19093")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_CLIENT_ID", "custom")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_DISCOVERY_TOPIC", "custom.topic")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_LINGER_MS", "12")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_QUEUE", "64")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_MAX_RECORD_BYTES", "131072")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_STATS_PATH", "/tmp/custom-eventbus.stats")
	cfg, err := ConfigFromEnv("sensor-a", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || len(cfg.Brokers) != 2 || cfg.ClientID != "custom" || cfg.DiscoveryTopic != "custom.topic" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.Linger != 12*time.Millisecond || cfg.Queue != 64 || cfg.MaxRecordBytes != 131072 {
		t.Fatalf("config bounds = %+v", cfg)
	}
	if cfg.StatsPath != "/tmp/custom-eventbus.stats" {
		t.Fatalf("stats path = %q", cfg.StatsPath)
	}
}

func TestConfigRejectsInvalidBounds(t *testing.T) {
	clearEventBusEnv(t)
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_SHADOW", "true")
	t.Setenv("PROXY_SENTINEL_EVENT_BUS_BROKERS", "127.0.0.1:19092")
	for _, tc := range []struct {
		key   string
		value string
	}{
		{"PROXY_SENTINEL_EVENT_BUS_QUEUE", "0"},
		{"PROXY_SENTINEL_EVENT_BUS_QUEUE", "999999"},
		{"PROXY_SENTINEL_EVENT_BUS_LINGER_MS", "-1"},
		{"PROXY_SENTINEL_EVENT_BUS_MAX_RECORD_BYTES", "1024"},
		{"PROXY_SENTINEL_EVENT_BUS_SHADOW", "not-a-bool"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			clearEventBusEnv(t)
			t.Setenv("PROXY_SENTINEL_EVENT_BUS_BROKERS", "127.0.0.1:19092")
			t.Setenv(tc.key, tc.value)
			if _, err := ConfigFromEnv("sensor-a", t.TempDir()); err == nil {
				t.Fatalf("expected error for %s=%s", tc.key, tc.value)
			}
		})
	}
}
