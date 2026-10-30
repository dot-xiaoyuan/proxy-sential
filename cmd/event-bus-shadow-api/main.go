package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type shadowAPI struct {
	pool *pgxpool.Pool
	rdb  *redis.Client
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18084", "listen address")
	pgDSN := flag.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	redisAddr := flag.String("redis-addr", "127.0.0.1:16401", "Redis address")
	redisDB := flag.Int("redis-db", 15, "Redis database")
	flag.Parse()
	if strings.TrimSpace(*pgDSN) == "" {
		fmt.Fprintln(os.Stderr, "event-bus-shadow-api requires postgres-dsn")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, *pgDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-shadow-api:", err)
		os.Exit(2)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-shadow-api:", err)
		os.Exit(2)
	}
	rdb := redis.NewClient(&redis.Options{Addr: *redisAddr, DB: *redisDB, DialTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second})
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		fmt.Fprintln(os.Stderr, "event-bus-shadow-api:", err)
		os.Exit(2)
	}
	api := &shadowAPI{pool: pool, rdb: rdb}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", api.health)
	mux.HandleFunc("/v1/shadow/current/", api.current)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("event-bus-shadow-api listening on %s", *addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("event-bus-shadow-api: %v", err)
		os.Exit(1)
	}
}

func (a *shadowAPI) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.pool.Ping(ctx); err != nil {
		http.Error(w, "postgres unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := a.rdb.Ping(ctx).Err(); err != nil {
		http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (a *shadowAPI) current(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/v1/shadow/current/")
	key = strings.TrimSpace(key)
	if key == "" || strings.Contains(key, "/") {
		http.Error(w, "device key required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	raw, err := a.rdb.Get(ctx, "ps:disc:current:"+key).Bytes()
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Shadow-Source", "redis")
		_, _ = w.Write(raw)
		return
	}
	if err != redis.Nil {
		http.Error(w, "redis read failed", http.StatusBadGateway)
		return
	}
	var value []byte
	err = a.pool.QueryRow(ctx, `SELECT jsonb_build_object(
        'device_key',device_key,'last_seen',last_seen,'fact_count',fact_count,
        'expired_fact_count',expired_fact_count,'facts',facts,'updated_at',updated_at)::text
        FROM discovery_device_current_shadow WHERE device_key=$1`, key).Scan(&value)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var compact any
	if json.Unmarshal(value, &compact) != nil {
		http.Error(w, "invalid shadow row", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Shadow-Source", "postgres")
	_, _ = w.Write(value)
}
