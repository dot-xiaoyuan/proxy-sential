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
	var lastFactVersion int64
	var lastExpiry time.Time
	var lastExpiryDeviceKey string
	if err := tx.QueryRow(ctx, `SELECT last_fact_change_version,last_fact_expiry_at,last_fact_expiry_device_key
FROM discovery_device_current_shadow_state WHERE id = TRUE FOR UPDATE`).Scan(&lastFactVersion, &lastExpiry, &lastExpiryDeviceKey); err != nil {
		return fmt.Errorf("read current shadow state: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT device_key,fact_change_version FROM discovery_service_facts_shadow
WHERE fact_change_version>$1
ORDER BY fact_change_version,device_key LIMIT 1000`, lastFactVersion)
	if err != nil {
		return fmt.Errorf("find changed devices: %w", err)
	}
	devices := []string{}
	seenDevices := make(map[string]struct{})
	maxFactVersion := lastFactVersion
	for rows.Next() {
		var device string
		var version int64
		if err := rows.Scan(&device, &version); err != nil {
			rows.Close()
			return err
		}
		if _, seen := seenDevices[device]; !seen {
			devices = append(devices, device)
			seenDevices[device] = struct{}{}
		}
		maxFactVersion = version
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	expiryRows, err := tx.Query(ctx, `SELECT device_key,valid_until FROM discovery_service_facts_shadow
WHERE NOT withdrawn AND valid_until IS NOT NULL
  AND (valid_until,device_key)>($1,$2) AND valid_until<=now()
ORDER BY valid_until,device_key LIMIT 1000`, lastExpiry, lastExpiryDeviceKey)
	if err != nil {
		return fmt.Errorf("find expired current facts: %w", err)
	}
	expiryKeys := []string{}
	expirySeen := make(map[string]struct{})
	maxExpiry, maxExpiryDeviceKey := lastExpiry, lastExpiryDeviceKey
	for expiryRows.Next() {
		var device string
		var until time.Time
		if err := expiryRows.Scan(&device, &until); err != nil {
			expiryRows.Close()
			return err
		}
		if _, seen := expirySeen[device]; !seen {
			expiryKeys = append(expiryKeys, device)
			expirySeen[device] = struct{}{}
		}
		maxExpiry, maxExpiryDeviceKey = until, device
	}
	if err := expiryRows.Err(); err != nil {
		expiryRows.Close()
		return err
	}
	expiryRows.Close()
	streamKeys, err := reconcileStreamCurrent(ctx, tx)
	if err != nil {
		return err
	}
	allKeys := append(append(append([]string(nil), devices...), expiryKeys...), streamKeys...)
	// Stream document updates do not change event-bus facts. Hydrate those
	// facts only when their own change or expiry cursor advances.
	factKeys := append(append([]string(nil), devices...), expiryKeys...)
	if err := upsertFactCurrent(ctx, tx, factKeys); err != nil {
		return err
	}
	if err := upsertStreamFactCurrent(ctx, tx, allKeys); err != nil {
		return err
	}
	if err := pruneChangedCurrent(ctx, tx, allKeys); err != nil {
		return err
	}
	staleKeys, err := clearInactiveCurrent(ctx, tx)
	if err != nil {
		return err
	}
	if len(devices) > 0 || len(expiryKeys) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE discovery_device_current_shadow_state
SET last_fact_change_version=$1,last_fact_expiry_at=$2,last_fact_expiry_device_key=$3 WHERE id=TRUE`, maxFactVersion, maxExpiry, maxExpiryDeviceKey); err != nil {
			return fmt.Errorf("advance current shadow fact state: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if rdb != nil {
		if len(staleKeys) > 0 {
			cacheKeys := make([]string, len(staleKeys))
			for i, key := range staleKeys {
				cacheKeys[i] = "ps:disc:current:" + key
			}
			if err := rdb.Del(ctx, cacheKeys...).Err(); err != nil {
				log.Printf("event-bus-current-shadow: stale Redis eviction failed: %v", err)
			}
		}
		if err := writeRedis(ctx, pool, rdb, append(allKeys, staleKeys...), ttl); err != nil {
			log.Printf("event-bus-current-shadow: Redis write failed: %v", err)
		}
	}
	if len(devices)+len(expiryKeys)+len(streamKeys)+len(staleKeys) > 0 {
		log.Printf("event-bus-current-shadow: changed_facts=%d expired_facts=%d stream=%d inactive=%d fact_version=%d", len(devices), len(expiryKeys), len(streamKeys), len(staleKeys), maxFactVersion)
	}
	return nil
}

func warmRedis(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, ttl time.Duration) error {
	const pageSize = 500
	cursor := ""
	for {
		rows, err := pool.Query(ctx, `SELECT device_key FROM discovery_device_current_shadow
WHERE device_key>$1 ORDER BY device_key LIMIT $2`, cursor, pageSize)
		if err != nil {
			return err
		}
		devices := make([]string, 0, pageSize)
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
		if err := writeRedis(ctx, pool, rdb, devices, ttl); err != nil {
			return err
		}
		cursor = devices[len(devices)-1]
		if len(devices) < pageSize {
			return nil
		}
	}
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
