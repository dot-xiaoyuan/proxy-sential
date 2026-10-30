package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
	mux.HandleFunc("/v1/shadow/devices", api.devices)
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

func (a *shadowAPI) devices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = value
	}
	window := 24 * time.Hour
	if raw := r.URL.Query().Get("window"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value < 10*time.Minute || value > 30*24*time.Hour {
			http.Error(w, "invalid window", http.StatusBadRequest)
			return
		}
		window = value
	}
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	pattern := ""
	if search != "" {
		pattern = "%" + search + "%"
	}
	var cursorTime string
	var cursorKey string
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		var cursor struct {
			Time time.Time `json:"t"`
			Key  string    `json:"k"`
		}
		if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.Key == "" || cursor.Time.IsZero() {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		cursorTime = cursor.Time.UTC().Format(time.RFC3339Nano)
		cursorKey = cursor.Key
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := a.pool.Query(ctx, `
SELECT c.device_key,
       c.last_seen,
       coalesce(s.document, '{}'::jsonb) || jsonb_build_object(
           'id', c.device_key,
           'last_seen', c.last_seen,
           'current', true,
           'generation', 'eventbus',
           'freshness', 'new',
           'fact_count', c.fact_count,
           'expired_fact_count', c.expired_fact_count,
           'facts', c.facts)
FROM discovery_device_current_shadow c
LEFT JOIN LATERAL (
    SELECT s.document
    FROM stream_discovery_device_state s
    WHERE s.device_key = c.device_key
      AND EXISTS (SELECT 1 FROM stream_source_cutovers x WHERE x.epoch = s.epoch AND x.state = 'active')
    ORDER BY s.last_seen DESC
    LIMIT 1
) s ON true
WHERE c.last_seen >= now() - ($1::text)::interval
  AND ($2 = '' OR s.document->>'name' ILIKE $2 OR s.document->>'manufacturer' ILIKE $2
       OR s.document->>'model_name' ILIKE $2 OR c.facts::text ILIKE $2)
  AND ($3::text = '' OR c.last_seen < $3::timestamptz OR (c.last_seen = $3::timestamptz AND c.device_key > $4))
ORDER BY c.last_seen DESC, c.device_key
LIMIT $5`, fmt.Sprintf("%d seconds", int(window.Seconds())), pattern, cursorTime, cursorKey, limit+1)
	if err != nil {
		http.Error(w, "shadow query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	keys := []struct {
		Time time.Time
		Key  string
	}{}
	for rows.Next() {
		var key string
		var lastSeen time.Time
		var raw []byte
		if err := rows.Scan(&key, &lastSeen, &raw); err != nil {
			http.Error(w, "shadow decode failed", http.StatusInternalServerError)
			return
		}
		var item map[string]any
		if err := json.Unmarshal(raw, &item); err != nil {
			http.Error(w, "shadow decode failed", http.StatusInternalServerError)
			return
		}
		items = append(items, item)
		keys = append(keys, struct {
			Time time.Time
			Key  string
		}{lastSeen, key})
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "shadow read failed", http.StatusInternalServerError)
		return
	}
	more := len(items) > limit
	nextCursor := ""
	if more {
		items = items[:limit]
		cursor, _ := json.Marshal(map[string]any{"t": keys[limit-1].Time, "k": keys[limit-1].Key})
		nextCursor = base64.RawURLEncoding.EncodeToString(cursor)
	}
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]any{"items": items, "has_more": more, "next_cursor": nextCursor, "limit": limit, "window": window.String()})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
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
