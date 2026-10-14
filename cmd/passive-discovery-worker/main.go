// Dedicated passive discovery process; resource limits belong to its systemd unit.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/store"
	"strings"
	"syscall"
	"time"
)

func main() {
	sensor := flag.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "sensor identifier")
	flag.Parse()
	if strings.TrimSpace(*sensor) == "" || strings.TrimSpace(os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")) == "" || strings.TrimSpace(os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN")) == "" {
		fmt.Fprintln(os.Stderr, "sensor and database connections are required")
		os.Exit(1)
	}
	if _, err := discovery.ParseCaptureCIDRs(os.Getenv("PROXY_SENTINEL_DISCOVERY_CIDRS")); err != nil {
		fmt.Fprintln(os.Stderr, "valid discovery CIDRs are required")
		os.Exit(1)
	}
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, SensorID: *sensor, CollectorKind: "passive-discovery", PostgresDSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), ClickHouseDSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), RequestTimeout: 45 * time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, "passive discovery storage initialization failed")
		os.Exit(1)
	}
	defer backend.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	backend.RunPassiveDiscoveryMaterializer(ctx, *sensor)
}
