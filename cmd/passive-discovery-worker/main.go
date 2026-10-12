package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"proxy-sentinel/internal/store"
	"strings"
	"syscall"
	"time"
)

func main() {
	sensorID := flag.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "sensor identifier")
	flag.Parse()
	if strings.TrimSpace(*sensorID) == "" ||
		strings.TrimSpace(os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")) == "" ||
		strings.TrimSpace(os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN")) == "" ||
		strings.TrimSpace(os.Getenv("PROXY_SENTINEL_DISCOVERY_CIDRS")) == "" {
		log.Fatal("sensor, database connections, and discovery CIDRs are required")
	}
	backend, err := store.NewDBStore(store.Options{
		Mode: store.ModeDB, SensorID: *sensorID,
		CollectorKind:  "read-model-passive-discovery",
		PostgresDSN:    os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"),
		ClickHouseDSN:  os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"),
		RequestTimeout: 70 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer backend.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	backend.RunPassiveDiscoveryMaterializer(ctx, *sensorID)
}
