package main

import (
	"context"
	"encoding/json"
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
	"github.com/redis/go-redis/v9"
)

func main() {
	dsn := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	interval := flag.Duration("interval", 5*time.Second, "aggregation interval")
	once := flag.Bool("once", false, "run one aggregation and exit")
	redisAddr := flag.String("redis-addr", "", "optional Redis address for hot state")
	redisDB := flag.Int("redis-db", 15, "Redis database for hot state")
	redisTTL := flag.Duration("redis-ttl", 5*time.Minute, "Redis hot-state TTL")
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
	var rdb *redis.Client
	if strings.TrimSpace(*redisAddr) != "" {
		if *redisDB < 0 || *redisDB > 15 {
			fmt.Fprintln(os.Stderr, "event-bus-current-shadow: redis-db must be 0..15")
			os.Exit(2)
		}
		rdb = redis.NewClient(&redis.Options{
			Addr:         strings.TrimSpace(*redisAddr),
			DB:           *redisDB,
			DialTimeout:  2 * time.Second,
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		})
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("event-bus-current-shadow: Redis unavailable, continuing without hot state: %v", err)
			_ = rdb.Close()
			rdb = nil
		} else {
			defer rdb.Close()
			if err := warmRedis(ctx, pool, rdb, *redisTTL); err != nil {
				log.Printf("event-bus-current-shadow: Redis warm failed: %v", err)
			}
		}
	}
	if *once {
		if err := aggregate(ctx, pool, rdb, *redisTTL); err != nil {
			fmt.Fprintln(os.Stderr, "event-bus-current-shadow:", err)
			os.Exit(1)
		}
		return
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		if err := aggregate(ctx, pool, rdb, *redisTTL); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("event-bus-current-shadow: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func aggregate(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, ttl time.Duration) error {
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
INSERT INTO discovery_device_current_shadow(device_key,last_seen,fact_count,expired_fact_count,facts,updated_at)
SELECT f.device_key,
       GREATEST(max(f.observed_at),COALESCE((SELECT max(s.last_seen) FROM stream_discovery_device_state s JOIN stream_source_cutovers c ON c.epoch=s.epoch AND c.state='active' WHERE s.device_key=f.device_key),max(f.observed_at))),
       count(*) FILTER (WHERE f.withdrawn = FALSE AND (f.valid_until IS NULL OR f.valid_until > now()))::int,
       count(*) FILTER (WHERE f.withdrawn = TRUE OR (f.valid_until IS NOT NULL AND f.valid_until <= now()))::int,
       coalesce(jsonb_object_agg(f.fact_key, jsonb_build_object(
           'event_id', f.event_id,
           'protocol', f.protocol,
           'ip', f.ip,
           'mac', f.mac,
           'observed_at', f.observed_at,
           'valid_until', f.valid_until,
           'withdrawn', f.withdrawn,
           'content_hash', f.content_hash,
           'version', f.version))
           FILTER (WHERE f.withdrawn = FALSE AND (f.valid_until IS NULL OR f.valid_until > now())), '{}'::jsonb),
       now()
FROM discovery_service_facts_shadow f
WHERE f.device_key = ANY($1::text[])
GROUP BY f.device_key
ON CONFLICT (device_key) DO UPDATE SET
    last_seen = EXCLUDED.last_seen,
    fact_count = EXCLUDED.fact_count,
    expired_fact_count = EXCLUDED.expired_fact_count,
    facts = EXCLUDED.facts,
    updated_at = now()`, devices)
	if err != nil {
		return fmt.Errorf("aggregate device current shadow: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE discovery_device_current_shadow c
SET last_seen=s.last_seen, updated_at=now()
FROM (
 SELECT s.device_key,max(s.last_seen) AS last_seen
 FROM stream_discovery_device_state s
 JOIN stream_source_cutovers c ON c.epoch=s.epoch AND c.state='active'
 WHERE s.last_seen>now()-interval '10 minutes'
 GROUP BY s.device_key
) s
WHERE c.device_key=s.device_key AND s.last_seen>c.last_seen`); err != nil {
		return fmt.Errorf("refresh current last seen: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE discovery_protocol_runtime r
SET enabled=true,last_seen=s.last_seen,last_success=s.last_seen,updated_at=now()
FROM (
 SELECT max(f.observed_at) AS last_seen
 FROM stream_discovery_facts f
 JOIN stream_source_cutovers c ON c.epoch=f.epoch AND c.state='active'
 WHERE f.protocol='dhcp'
) s
WHERE r.protocol='dhcp' AND s.last_seen IS NOT NULL`); err != nil {
		return fmt.Errorf("refresh DHCP protocol runtime: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE discovery_device_current_shadow_state SET last_updated_at = $1 WHERE id = TRUE`, maxUpdated); err != nil {
		return fmt.Errorf("advance current shadow state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if rdb != nil {
		if err := writeRedis(ctx, pool, rdb, devices, ttl); err != nil {
			log.Printf("event-bus-current-shadow: Redis write failed: %v", err)
		}
	}
	log.Printf("event-bus-current-shadow: upserted=%d through=%s", len(devices), maxUpdated.UTC().Format(time.RFC3339Nano))
	return nil
}

func warmRedis(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, ttl time.Duration) error {
	rows, err := pool.Query(ctx, `SELECT device_key FROM discovery_device_current_shadow`)
	if err != nil {
		return err
	}
	devices := []string{}
	for rows.Next() {
		var device string
		if err := rows.Scan(&device); err != nil {
			rows.Close()
			return err
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(devices) == 0 {
		return nil
	}
	return writeRedis(ctx, pool, rdb, devices, ttl)
}

func writeRedis(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, devices []string, ttl time.Duration) error {
	if len(devices) == 0 {
		return nil
	}
	rows, err := pool.Query(ctx, `SELECT device_key,last_seen,fact_count,expired_fact_count,facts,updated_at
FROM discovery_device_current_shadow WHERE device_key = ANY($1::text[])`, devices)
	if err != nil {
		return err
	}
	pipe := rdb.Pipeline()
	count := 0
	for rows.Next() {
		var device string
		var lastSeen, updatedAt time.Time
		var factCount, expired int
		var facts []byte
		if err := rows.Scan(&device, &lastSeen, &factCount, &expired, &facts, &updatedAt); err != nil {
			rows.Close()
			return err
		}
		payload, err := json.Marshal(map[string]any{
			"device_key":         device,
			"last_seen":          lastSeen.UTC(),
			"fact_count":         factCount,
			"expired_fact_count": expired,
			"facts":              json.RawMessage(facts),
			"updated_at":         updatedAt.UTC(),
		})
		if err != nil {
			rows.Close()
			return err
		}
		pipe.Set(ctx, "ps:disc:current:"+device, payload, ttl)
		count++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	log.Printf("event-bus-current-shadow: redis keys=%d ttl=%s", count, ttl)
	return nil
}
