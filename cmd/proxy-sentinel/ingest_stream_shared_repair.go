package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"proxy-sentinel/internal/store"
)

func runIngestStreamSharedRepair(args []string) error {
	fs := flag.NewFlagSet("ingest stream-shared-repair", flag.ContinueOnError)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered capture sensor")
	path := fs.String("packet-source", "", "the active packet source file")
	epoch := fs.String("packet-epoch", "", "audited repaired packet binding epoch")
	scopeFile := fs.String("capture-scope-config", os.Getenv("PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG"), "registered capture scope")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse DSN")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sensor == "" || filepath.Base(*path) != "ttl.jsonl" || *epoch == "" || *scopeFile == "" || *postgresDSN == "" || *clickhouseDSN == "" {
		return errors.New("shared repair requires the active packet source, scope and storage")
	}
	scope, _, err := loadCaptureScopeWithHash(*scopeFile)
	if err != nil {
		return err
	}
	if scope == nil || scope.SensorID != *sensor || time.Now().Before(scope.ValidFrom) || !time.Now().Before(scope.ValidUntil) {
		return errors.New("shared repair requires the active capture scope")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", *postgresDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	// The session lock serializes repair commands while the second connection
	// executes short, independent receipt transactions.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var locked bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended('shared-packet-repair-run:'||$1,0))`, *epoch).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return errors.New("packet repair for this epoch is already running")
	}
	ch, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: *clickhouseDSN, RequestTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	queue := store.StreamSharedJobQueue{DB: db}
	result, err := queue.RepairSharedPacketPage(ctx, ch, *sensor, scope.ID(), *path, *epoch, 180*time.Second)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
