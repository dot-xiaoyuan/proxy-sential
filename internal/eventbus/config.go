package eventbus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultDiscoveryTopic = "ps.discovery.events.v1"

// Config is the shadow-publisher configuration. It is intentionally separate
// from the future primary consumer configuration so that enabling a shadow
// stream can never change the discovery read path.
type Config struct {
	Enabled       bool
	ShadowEnabled bool
	// ReliableSource is an explicit per-source canary. Empty preserves the
	// existing best-effort shadow path and its non-blocking capture semantics.
	ReliableSource string
	Brokers        []string
	ClientID       string
	DiscoveryTopic string
	Linger         time.Duration
	Queue          int
	MaxRecordBytes int
	StatsPath      string
}

// ConfigFromEnv reads the event bus shadow settings. Invalid explicit settings
// are returned as errors; callers may disable only the shadow publisher while
// keeping capture running.
func ConfigFromEnv(node, statsDir string) (Config, error) {
	cfg := Config{
		ClientID:       "discovery-" + strings.TrimSpace(node),
		DiscoveryTopic: DefaultDiscoveryTopic,
		Linger:         5 * time.Millisecond,
		Queue:          8192,
		MaxRecordBytes: 900 << 10,
	}
	if statsDir != "" {
		cfg.StatsPath = filepath.Join(statsDir, "eventbus.stats")
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_STATS_PATH")); raw != "" {
		cfg.StatsPath = raw
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_SHADOW")); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return cfg, fmt.Errorf("invalid PROXY_SENTINEL_EVENT_BUS_SHADOW: %w", err)
		}
		cfg.Enabled = enabled
		cfg.ShadowEnabled = enabled
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_RELIABLE_SOURCE")); raw != "" {
		if raw != "passive-discovery" {
			return cfg, errors.New("PROXY_SENTINEL_EVENT_BUS_RELIABLE_SOURCE currently supports passive-discovery only")
		}
		cfg.ReliableSource = raw
		cfg.Enabled = true
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_CLIENT_ID")); raw != "" {
		cfg.ClientID = raw
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_DISCOVERY_TOPIC")); raw != "" {
		cfg.DiscoveryTopic = raw
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_BROKERS")); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			if broker := strings.TrimSpace(part); broker != "" {
				cfg.Brokers = append(cfg.Brokers, broker)
			}
		}
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_LINGER_MS")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 1000 {
			return cfg, errors.New("PROXY_SENTINEL_EVENT_BUS_LINGER_MS must be 0..1000")
		}
		cfg.Linger = time.Duration(value) * time.Millisecond
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_QUEUE")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 65536 {
			return cfg, errors.New("PROXY_SENTINEL_EVENT_BUS_QUEUE must be 1..65536")
		}
		cfg.Queue = value
	}
	if raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_EVENT_BUS_MAX_RECORD_BYTES")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 64<<10 || value > 1<<20 {
			return cfg, errors.New("PROXY_SENTINEL_EVENT_BUS_MAX_RECORD_BYTES must be 65536..1048576")
		}
		cfg.MaxRecordBytes = value
	}
	if !cfg.Enabled {
		return cfg, nil
	}
	if len(cfg.Brokers) == 0 {
		return cfg, errors.New("PROXY_SENTINEL_EVENT_BUS_BROKERS is required when shadow publishing is enabled")
	}
	if cfg.ClientID == "" {
		return cfg, errors.New("event bus client id is empty")
	}
	if cfg.DiscoveryTopic == "" {
		return cfg, errors.New("event bus discovery topic is empty")
	}
	return cfg, nil
}
