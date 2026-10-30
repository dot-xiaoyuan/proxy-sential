package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type currentRow struct {
	DeviceKey        string          `json:"device_key"`
	LastSeen         time.Time       `json:"last_seen"`
	FactCount        int             `json:"fact_count"`
	ExpiredFactCount int             `json:"expired_fact_count"`
	Facts            json.RawMessage `json:"facts"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

func main() {
	pgDSN := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	redisAddr := flag.String("redis-addr", "127.0.0.1:16401", "Redis address")
	redisDB := flag.Int("redis-db", 15, "Redis database")
	deviceKey := flag.String("device-key", "", "single device key; empty checks all devices")
	limit := flag.Int("limit", 100000, "maximum devices to check")
	flag.Parse()
	if strings.TrimSpace(*pgDSN) == "" || strings.TrimSpace(*redisAddr) == "" {
		fmt.Fprintln(os.Stderr, "event-bus-read-shadow requires postgres-dsn and redis-addr")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, *pgDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-read-shadow:", err)
		os.Exit(2)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-read-shadow:", err)
		os.Exit(2)
	}
	rdb := redis.NewClient(&redis.Options{Addr: *redisAddr, DB: *redisDB, DialTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second})
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-read-shadow:", err)
		os.Exit(2)
	}

	keys := []string{}
	if *deviceKey != "" {
		keys = append(keys, *deviceKey)
	} else {
		rows, err := pool.Query(ctx, `SELECT device_key FROM discovery_device_current_shadow ORDER BY device_key LIMIT $1`, *limit)
		if err != nil {
			fmt.Fprintln(os.Stderr, "event-bus-read-shadow:", err)
			os.Exit(1)
		}
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				fmt.Fprintln(os.Stderr, "event-bus-read-shadow:", err)
				os.Exit(1)
			}
			keys = append(keys, key)
		}
		rows.Close()
	}
	mismatches := 0
	missing := 0
	for _, key := range keys {
		pgRow, err := readPostgres(ctx, pool, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "postgres key=%s: %v\n", key, err)
			mismatches++
			continue
		}
		raw, err := rdb.Get(ctx, "ps:disc:current:"+key).Bytes()
		if err == redis.Nil {
			missing++
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "redis key=%s: %v\n", key, err)
			mismatches++
			continue
		}
		var cacheRow currentRow
		if err := json.Unmarshal(raw, &cacheRow); err != nil {
			fmt.Fprintf(os.Stderr, "decode redis key=%s: %v\n", key, err)
			mismatches++
			continue
		}
		if !sameRow(pgRow, cacheRow) {
			fmt.Fprintf(os.Stderr, "mismatch key=%s\n", key)
			mismatches++
		}
	}
	fmt.Printf("checked=%d missing=%d mismatches=%d\n", len(keys), missing, mismatches)
	if mismatches > 0 || missing > 0 {
		os.Exit(1)
	}
}

func readPostgres(ctx context.Context, pool *pgxpool.Pool, key string) (currentRow, error) {
	var row currentRow
	var facts []byte
	err := pool.QueryRow(ctx, `SELECT device_key,last_seen,fact_count,expired_fact_count,facts,updated_at
FROM discovery_device_current_shadow WHERE device_key=$1`, key).
		Scan(&row.DeviceKey, &row.LastSeen, &row.FactCount, &row.ExpiredFactCount, &facts, &row.UpdatedAt)
	if err != nil {
		return row, err
	}
	row.Facts = append(json.RawMessage(nil), facts...)
	return row, nil
}

func sameRow(a, b currentRow) bool {
	if a.DeviceKey != b.DeviceKey || a.FactCount != b.FactCount || a.ExpiredFactCount != b.ExpiredFactCount {
		return false
	}
	if !a.LastSeen.Equal(b.LastSeen) || !a.UpdatedAt.Equal(b.UpdatedAt) {
		return false
	}
	var left, right any
	if err := json.Unmarshal(a.Facts, &left); err != nil {
		return false
	}
	if err := json.Unmarshal(b.Facts, &right); err != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}
