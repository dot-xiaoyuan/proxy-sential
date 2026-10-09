package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/legacy4k"
)

type config struct {
	onlineAddr, onlinePasswordFile string
	eventAddr, eventPasswordFile   string
	eventList, onlineList          string
	endpoint, tokenFile            string
	source, sensor, campus, domain string
	processingList, deadList       string
	healthAddr                     string
	batchSize, maxRecords          int
	reconcile                      time.Duration
	restoreProcessing              bool
}

type runtimeState struct {
	mu                 sync.RWMutex
	startedAt          time.Time
	lastEventAt        time.Time
	lastSnapshotAt     time.Time
	lastErrorAt        time.Time
	lastErrorType      string
	sourceQueue        int64
	processingQueue    int64
	badMessages        uint64
	committedMessages  uint64
	onlineSessions     int
	invalidOnlineRows  int
	consecutiveFailure int
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := parseConfig()
	if err != nil {
		return err
	}
	eventPassword, err := readSecret(cfg.eventPasswordFile, true)
	if err != nil {
		return fmt.Errorf("read notification Redis credential: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eventClient := redis.NewClient(&redis.Options{Addr: cfg.eventAddr, Password: eventPassword, ReadTimeout: 35 * time.Second, WriteTimeout: 5 * time.Second})
	defer eventClient.Close()
	if err = eventClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("notification Redis unavailable: %w", err)
	}
	if cfg.restoreProcessing {
		return restoreProcessing(ctx, eventClient, cfg.eventList, cfg.processingList)
	}
	onlinePassword, err := readSecret(cfg.onlinePasswordFile, true)
	if err != nil {
		return fmt.Errorf("read online Redis credential: %w", err)
	}
	token, err := readSecret(cfg.tokenFile, true)
	if err != nil {
		return fmt.Errorf("read identity token: %w", err)
	}
	onlineRaw := redis.NewClient(&redis.Options{Addr: cfg.onlineAddr, Password: onlinePassword, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second})
	defer onlineRaw.Close()
	onlineClient := legacy4k.NewRedisOnlineClient(&redis.Options{Addr: cfg.onlineAddr, Password: onlinePassword, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second})
	defer onlineClient.Close()
	if err = onlineRaw.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("online Redis unavailable: %w", err)
	}
	info, err := onlineRaw.Info(ctx, "server").Result()
	if err != nil {
		return fmt.Errorf("read online Redis instance: %w", err)
	}
	instanceID := runID(info)
	if instanceID == "" {
		return fmt.Errorf("online Redis instance id unavailable")
	}
	sender := legacy4k.Sender{Endpoint: cfg.endpoint, Token: token, SensorID: cfg.sensor, Source: cfg.source, CampusID: cfg.campus, AccessDomain: cfg.domain}
	state := &runtimeState{startedAt: time.Now().UTC()}
	server := startHealthServer(cfg.healthAddr, state)
	defer server.Shutdown(context.Background())
	logStatus("starting", map[string]any{"source": cfg.source, "sensor_id": cfg.sensor, "event_list": cfg.eventList})

	// Recover processing before moving source messages. This preserves FIFO and
	// guarantees at-least-once delivery across crashes.
	for {
		processed, processErr := processBatch(ctx, eventClient, sender, cfg, instanceID, state)
		if processErr != nil {
			markFailure(state, processErr)
			if !waitContext(ctx, 2*time.Second) {
				return nil
			}
			continue
		}
		if !processed {
			break
		}
	}
	snapshotDelay := cfg.reconcile
	if err = submitSnapshot(ctx, onlineClient, sender, cfg, state); err != nil {
		markFailure(state, err)
		logStatus("snapshot_failed", map[string]any{"error_type": errorType(err)})
		snapshotDelay = 10 * time.Second
	} else {
		logStatus("snapshot_committed", map[string]any{"source": cfg.source})
	}

	snapshotTimer := time.NewTimer(snapshotDelay)
	defer snapshotTimer.Stop()
	for {
		processed, processErr := processBatch(ctx, eventClient, sender, cfg, instanceID, state)
		if processErr != nil {
			markFailure(state, processErr)
			if !waitContext(ctx, 2*time.Second) {
				return nil
			}
			continue
		}
		if processed {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-snapshotTimer.C:
			if snapshotErr := submitSnapshot(ctx, onlineClient, sender, cfg, state); snapshotErr != nil {
				markFailure(state, snapshotErr)
				logStatus("snapshot_failed", map[string]any{"error_type": errorType(snapshotErr)})
				snapshotTimer.Reset(10 * time.Second)
			} else {
				logStatus("snapshot_committed", map[string]any{"source": cfg.source})
				snapshotTimer.Reset(cfg.reconcile)
			}
		default:
			_, moveErr := eventClient.BLMove(ctx, cfg.eventList, cfg.processingList, "LEFT", "RIGHT", 5*time.Second).Result()
			if moveErr != nil && moveErr != redis.Nil && !errors.Is(moveErr, context.Canceled) {
				markFailure(state, moveErr)
			}
		}
	}
}

func parseConfig() (config, error) {
	legacyAddr := os.Getenv("LEGACY_4K_REDIS_ADDR")
	legacyPassword := os.Getenv("LEGACY_4K_REDIS_PASSWORD_FILE")
	cfg := config{}
	flag.StringVar(&cfg.onlineAddr, "online-redis-addr", firstEnv(os.Getenv("NCU_ONLINE_REDIS_ADDR"), legacyAddr), "authoritative online Redis address")
	flag.StringVar(&cfg.onlinePasswordFile, "online-redis-password-file", firstEnv(os.Getenv("NCU_ONLINE_REDIS_PASSWORD_FILE"), legacyPassword), "0600 file containing the online Redis password")
	flag.StringVar(&cfg.eventAddr, "event-redis-addr", firstEnv(os.Getenv("NCU_EVENT_REDIS_ADDR"), legacyAddr), "notification Redis address")
	flag.StringVar(&cfg.eventPasswordFile, "event-redis-password-file", firstEnv(os.Getenv("NCU_EVENT_REDIS_PASSWORD_FILE"), legacyPassword), "0600 file containing the notification Redis password")
	flag.StringVar(&cfg.eventList, "event-list", os.Getenv("LEGACY_4K_EVENT_LIST"), "legacy online/offline FIFO list")
	flag.StringVar(&cfg.onlineList, "online-list", "list:rad_online", "authoritative online member list")
	flag.StringVar(&cfg.endpoint, "endpoint", os.Getenv("PROXY_SENTINEL_URL"), "Proxy Sentinel control-plane URL")
	flag.StringVar(&cfg.tokenFile, "token-file", os.Getenv("PROXY_SENTINEL_IDENTITY_TOKEN_FILE"), "0600 identity token file")
	flag.StringVar(&cfg.source, "source", "ncu-srun4k", "registered identity source")
	flag.StringVar(&cfg.sensor, "sensor-id", "ncu-auth-redis", "registered sensor")
	flag.StringVar(&cfg.campus, "campus-id", "ncu", "campus scope")
	flag.StringVar(&cfg.domain, "access-domain", "campus-auth", "access domain scope")
	flag.StringVar(&cfg.healthAddr, "health-addr", "127.0.0.1:18082", "local health and metrics listener")
	flag.IntVar(&cfg.batchSize, "batch-size", 500, "maximum notification batch size")
	flag.IntVar(&cfg.maxRecords, "max-records", 100000, "maximum complete online inventory")
	flag.DurationVar(&cfg.reconcile, "reconcile-interval", 30*time.Minute, "complete inventory calibration interval")
	flag.BoolVar(&cfg.restoreProcessing, "restore-processing", false, "move unacknowledged processing messages back before the source FIFO and exit")
	flag.Parse()
	required := map[string]string{"event-redis-addr": cfg.eventAddr, "event-redis-password-file": cfg.eventPasswordFile, "event-list": cfg.eventList}
	if !cfg.restoreProcessing {
		for name, value := range map[string]string{"online-redis-addr": cfg.onlineAddr, "online-redis-password-file": cfg.onlinePasswordFile, "endpoint": cfg.endpoint, "token-file": cfg.tokenFile, "source": cfg.source, "sensor-id": cfg.sensor, "campus-id": cfg.campus, "access-domain": cfg.domain} {
			required[name] = value
		}
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return cfg, fmt.Errorf("%s is required", name)
		}
	}
	if cfg.batchSize < 1 || cfg.batchSize > 500 || cfg.maxRecords < 1 || cfg.maxRecords > 100000 || cfg.reconcile < time.Minute || cfg.reconcile > 24*time.Hour {
		return cfg, fmt.Errorf("invalid batch, inventory or reconciliation bound")
	}
	cfg.processingList = cfg.eventList + ":proxy-sentinel-processing"
	cfg.deadList = cfg.eventList + ":proxy-sentinel-dead-meta"
	return cfg, nil
}

func restoreProcessing(ctx context.Context, client *redis.Client, source, processing string) error {
	restored := 0
	for {
		_, err := client.LMove(ctx, processing, source, "RIGHT", "LEFT").Result()
		if err == redis.Nil {
			logStatus("processing_restored", map[string]any{"restored_messages": restored})
			return nil
		}
		if err != nil {
			return err
		}
		restored++
	}
}

func processBatch(ctx context.Context, client *redis.Client, sender legacy4k.Sender, cfg config, instanceID string, state *runtimeState) (bool, error) {
	pending, err := client.LLen(ctx, cfg.processingList).Result()
	if err != nil {
		return false, err
	}
	for pending < int64(cfg.batchSize) {
		_, moveErr := client.LMove(ctx, cfg.eventList, cfg.processingList, "LEFT", "RIGHT").Result()
		if moveErr == redis.Nil {
			break
		}
		if moveErr != nil {
			return false, moveErr
		}
		pending++
	}
	if pending == 0 {
		updateQueueMetrics(ctx, client, cfg, state)
		return false, nil
	}
	limit := int64(cfg.batchSize - 1)
	if pending < int64(cfg.batchSize) {
		limit = pending - 1
	}
	rawMessages, err := client.LRange(ctx, cfg.processingList, 0, limit).Result()
	if err != nil {
		return false, err
	}
	records := make([]map[string]string, 0, len(rawMessages))
	badMetadata := make([]string, 0)
	hasher := sha256.New()
	for _, raw := range rawMessages {
		hasher.Write([]byte(strconv.Itoa(len(raw))))
		hasher.Write([]byte{0})
		hasher.Write([]byte(raw))
		record, decodeErr := legacy4k.DecodeRecordForInstance(raw, instanceID, time.Now().UTC())
		if decodeErr != nil {
			sum := sha256.Sum256([]byte(raw))
			meta, _ := json.Marshal(map[string]any{"sha256": hex.EncodeToString(sum[:]), "length": len(raw), "error_type": errorType(decodeErr), "observed_at": time.Now().UTC().Format(time.RFC3339Nano)})
			badMetadata = append(badMetadata, string(meta))
			continue
		}
		records = append(records, record)
	}
	batchID := "legacy-4k-batch-" + hex.EncodeToString(hasher.Sum(nil))[:24]
	if err = sender.Send(ctx, records, batchID); err != nil {
		return true, err
	}
	_, err = client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, metadata := range badMetadata {
			pipe.RPush(ctx, cfg.deadList, metadata)
		}
		pipe.LTrim(ctx, cfg.processingList, int64(len(rawMessages)), -1)
		return nil
	})
	if err != nil {
		return true, err
	}
	state.mu.Lock()
	state.committedMessages += uint64(len(records))
	state.badMessages += uint64(len(badMetadata))
	state.lastEventAt = time.Now().UTC()
	state.consecutiveFailure = 0
	state.mu.Unlock()
	updateQueueMetrics(ctx, client, cfg, state)
	return true, nil
}

func submitSnapshot(ctx context.Context, client *legacy4k.RedisOnlineClient, sender legacy4k.Sender, cfg config, state *runtimeState) error {
	inventory, err := legacy4k.ReadOnlineInventoryStabilized(ctx, client, cfg.onlineList, cfg.maxRecords, 500, 3)
	if err != nil {
		return err
	}
	if err = sender.SendSnapshot(ctx, inventory, cfg.source, cfg.campus, cfg.domain, int(cfg.reconcile/time.Second)); err != nil {
		return err
	}
	state.mu.Lock()
	state.lastSnapshotAt = inventory.ObservedAt
	state.onlineSessions = len(inventory.Rows)
	state.invalidOnlineRows = inventory.SkippedInvalid
	state.consecutiveFailure = 0
	state.mu.Unlock()
	return nil
}

func startHealthServer(addr string, state *runtimeState) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		state.mu.RLock()
		ready := state.consecutiveFailure < 5
		body := map[string]any{"ready": ready, "source_queue": state.sourceQueue, "processing_queue": state.processingQueue, "online_sessions": state.onlineSessions, "invalid_online_rows": state.invalidOnlineRows, "last_event_at": state.lastEventAt, "last_snapshot_at": state.lastSnapshotAt, "consecutive_failures": state.consecutiveFailure}
		state.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "proxy_sentinel_ncu_auth_source_queue %d\nproxy_sentinel_ncu_auth_processing_queue %d\nproxy_sentinel_ncu_auth_bad_messages_total %d\nproxy_sentinel_ncu_auth_committed_messages_total %d\nproxy_sentinel_ncu_auth_online_sessions %d\nproxy_sentinel_ncu_auth_invalid_online_rows %d\nproxy_sentinel_ncu_auth_consecutive_failures %d\nproxy_sentinel_ncu_auth_snapshot_age_seconds %.0f\n", state.sourceQueue, state.processingQueue, state.badMessages, state.committedMessages, state.onlineSessions, state.invalidOnlineRows, state.consecutiveFailure, ageSeconds(state.lastSnapshotAt))
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			markFailure(state, err)
		}
	}()
	return server
}

func updateQueueMetrics(ctx context.Context, client *redis.Client, cfg config, state *runtimeState) {
	values, err := client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.LLen(ctx, cfg.eventList)
		pipe.LLen(ctx, cfg.processingList)
		return nil
	})
	if err != nil || len(values) != 2 {
		return
	}
	source, sourceErr := values[0].(*redis.IntCmd).Result()
	processing, processingErr := values[1].(*redis.IntCmd).Result()
	if sourceErr == nil && processingErr == nil {
		state.mu.Lock()
		state.sourceQueue, state.processingQueue = source, processing
		state.mu.Unlock()
	}
}

func markFailure(state *runtimeState, err error) {
	state.mu.Lock()
	state.lastErrorAt = time.Now().UTC()
	state.lastErrorType = errorType(err)
	state.consecutiveFailure++
	state.mu.Unlock()
	logStatus("operation_failed", map[string]any{"error_type": errorType(err)})
}

func errorType(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, legacy4k.ErrOnlineInventoryChanged) {
		return "online_inventory_changed"
	}
	if errors.Is(err, legacy4k.ErrOnlineResourceLimit) {
		return "resource_limit"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if strings.Contains(strings.ToLower(err.Error()), "json") {
		return "malformed_json"
	}
	return "operation_error"
}

func runID(info string) string {
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "run_id:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "run_id:"))
		}
	}
	return ""
}

func ageSeconds(at time.Time) float64 {
	if at.IsZero() {
		return -1
	}
	return time.Since(at).Seconds()
}

func readSecret(path string, required bool) (string, error) {
	if path == "" {
		if required {
			return "", fmt.Errorf("secret file is required")
		}
		return "", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("secret file permissions must be 0600 or stricter")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if required && value == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return value, nil
}

func firstEnv(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func logStatus(status string, fields map[string]any) {
	fields["status"] = status
	fields["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	_ = json.NewEncoder(os.Stdout).Encode(fields)
}
