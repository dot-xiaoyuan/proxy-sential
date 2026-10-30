package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	dsn := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	interval := flag.Duration("interval", 5*time.Second, "aggregation interval")
	once := flag.Bool("once", false, "run one aggregation and exit")
	flag.Parse()
	if strings.TrimSpace(*dsn) == "" || *interval < time.Second {
		fmt.Fprintln(os.Stderr, "event-bus-current-shadow requires postgres-dsn and interval >= 1s")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg, err := pgxpool.ParseConfig(*dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-current-shadow:", err)
		os.Exit(2)
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-current-shadow:", err)
		os.Exit(2)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-current-shadow:", err)
		os.Exit(2)
	}
	if *once {
		if err := aggregate(ctx, pool); err != nil {
			fmt.Fprintln(os.Stderr, "event-bus-current-shadow:", err)
			os.Exit(1)
		}
		return
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		if err := aggregate(ctx, pool); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("event-bus-current-shadow: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func aggregate(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var lastUpdated time.Time
	if err := tx.QueryRow(ctx, `SELECT last_updated_at FROM discovery_device_current_shadow_state WHERE id = TRUE FOR UPDATE`).Scan(&lastUpdated); err != nil {
		return fmt.Errorf("read current shadow state: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT device_key, max(updated_at) FROM discovery_service_facts_shadow WHERE updated_at > $1 GROUP BY device_key`, lastUpdated)
	if err != nil {
		return fmt.Errorf("find changed devices: %w", err)
	}
	devices := []string{}
	maxUpdated := lastUpdated
	for rows.Next() {
		var device string
		var updated time.Time
		if err := rows.Scan(&device, &updated); err != nil {
			rows.Close()
			return err
		}
		devices = append(devices, device)
		if updated.After(maxUpdated) {
			maxUpdated = updated
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(devices) == 0 {
		return tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO discovery_device_current_shadow(device_key,last_seen,fact_count,facts,updated_at)
SELECT f.device_key,
       max(f.observed_at),
       count(*)::int,
       jsonb_object_agg(f.fact_key, jsonb_build_object(
           'event_id', f.event_id,
           'protocol', f.protocol,
           'ip', f.ip,
           'mac', f.mac,
           'observed_at', f.observed_at,
           'valid_until', f.valid_until,
           'withdrawn', f.withdrawn,
           'content_hash', f.content_hash,
           'version', f.version)),
       now()
FROM discovery_service_facts_shadow f
WHERE f.device_key = ANY($1::text[])
GROUP BY f.device_key
ON CONFLICT (device_key) DO UPDATE SET
    last_seen = EXCLUDED.last_seen,
    fact_count = EXCLUDED.fact_count,
    facts = EXCLUDED.facts,
    updated_at = now()`, devices)
	if err != nil {
		return fmt.Errorf("aggregate device current shadow: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE discovery_device_current_shadow_state SET last_updated_at = $1 WHERE id = TRUE`, maxUpdated); err != nil {
		return fmt.Errorf("advance current shadow state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	log.Printf("event-bus-current-shadow: upserted=%d through=%s", len(devices), maxUpdated.UTC().Format(time.RFC3339Nano))
	return nil
}
