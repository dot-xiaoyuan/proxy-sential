package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
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
	mu                          sync.RWMutex
	startedAt                   time.Time
	lastEventAt                 time.Time
	lastSnapshotAttemptAt       time.Time
	lastSnapshotAt              time.Time
	lastErrorAt                 time.Time
	lastErrorType               string
	activeHost                  string
	activeConfigVersion         int64
	instanceID                  string
	overallState                string
	onlineChannelState          string
	eventChannelState           string
	snapshotState               string
	sourceQueue                 int64
	processingQueue             int64
	onlineMembers               int64
	badMessages                 uint64
	committedMessages           uint64
	onlineSessions              int
	invalidOnlineRows           int
	eventConsecutiveFailures    int
	snapshotConsecutiveFailures int
}

type bridgeRuntimeConfig struct {
	Host                     string `json:"host"`
	ConfigVersion            int64  `json:"config_version"`
	OnlineRedisAddr          string `json:"online_redis_addr"`
	EventRedisAddr           string `json:"event_redis_addr"`
	OnlineList               string `json:"online_list"`
	EventList                string `json:"event_list"`
	Source                   string `json:"source"`
	SensorID                 string `json:"sensor_id"`
	CampusID                 string `json:"campus_id"`
	AccessDomain             string `json:"access_domain"`
	BatchSize                int    `json:"batch_size"`
	ReconcileIntervalSeconds int    `json:"reconcile_interval_seconds"`
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
	activeHost, _, _ := net.SplitHostPort(cfg.onlineAddr)
	state := &runtimeState{startedAt: time.Now().UTC(), activeHost: activeHost, instanceID: instanceID, overallState: "starting", onlineChannelState: "healthy", eventChannelState: "healthy", snapshotState: "pending"}
	server := startHealthServer(cfg.healthAddr, state)
	defer server.Shutdown(context.Background())
	logStatus("starting", map[string]any{"source": cfg.source, "sensor_id": cfg.sensor, "event_list": cfg.eventList})

	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		runEventWorker(ctx, eventClient, sender, cfg, state)
	}()
	go func() {
		defer workers.Done()
		runSnapshotWorker(ctx, sender, cfg, onlinePassword, token, state)
	}()
	go func() {
		defer workers.Done()
		runHeartbeatWorker(ctx, cfg, token, state)
	}()
	<-ctx.Done()
	workers.Wait()
	return nil
}

func runEventWorker(ctx context.Context, client *redis.Client, sender legacy4k.Sender, cfg config, state *runtimeState) {
	for {
		state.mu.RLock()
		instanceID := state.instanceID
		state.mu.RUnlock()
		processed, err := processBatch(ctx, client, sender, cfg, instanceID, state)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			markEventFailure(state, err)
			if !waitContext(ctx, 2*time.Second) {
				return
			}
			continue
		}
		if processed {
			continue
		}
		_, err = client.BLMove(ctx, cfg.eventList, cfg.processingList, "LEFT", "RIGHT", 5*time.Second).Result()
		if err != nil && err != redis.Nil && !errors.Is(err, context.Canceled) {
			markEventFailure(state, err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func runSnapshotWorker(ctx context.Context, sender legacy4k.Sender, base config, password, token string, state *runtimeState) {
	activeAddr := base.onlineAddr
	activeVersion := int64(0)
	desired := bridgeRuntimeConfig{Host: state.activeHost, OnlineRedisAddr: activeAddr, ConfigVersion: activeVersion, OnlineList: base.onlineList, Source: base.source, SensorID: base.sensor, CampusID: base.campus, AccessDomain: base.domain, ReconcileIntervalSeconds: int(base.reconcile / time.Second)}
	nextActiveSnapshot := time.Now()
	nextSwitchAttempt := time.Now()
	nextConfig := time.Time{}
	for ctx.Err() == nil {
		now := time.Now()
		if !now.Before(nextConfig) {
			if fetched, err := fetchBridgeRuntimeConfig(ctx, base.endpoint, token); err == nil && fetched.OnlineRedisAddr != "" {
				desired = fetched
			}
			nextConfig = now.Add(5 * time.Second)
		}
		isSwitch := desired.OnlineRedisAddr != activeAddr || desired.ConfigVersion != activeVersion
		attemptSwitch := isSwitch && !now.Before(nextSwitchAttempt)
		attemptActiveSnapshot := !now.Before(nextActiveSnapshot)
		if attemptSwitch || attemptActiveSnapshot {
			targetAddr := activeAddr
			targetVersion := activeVersion
			if attemptSwitch {
				targetAddr, targetVersion = desired.OnlineRedisAddr, desired.ConfigVersion
				state.mu.Lock()
				state.overallState = "switching"
				state.mu.Unlock()
			}
			attemptCfg := base
			attemptCfg.onlineAddr = targetAddr
			if desired.OnlineList != "" {
				attemptCfg.onlineList = desired.OnlineList
			}
			if desired.ReconcileIntervalSeconds > 0 {
				attemptCfg.reconcile = time.Duration(desired.ReconcileIntervalSeconds) * time.Second
			}
			started := time.Now().UTC()
			runID := legacy4k.StableID(strings.Join([]string{"snapshot", targetAddr, started.Format(time.RFC3339Nano)}, "\x00"))
			runKind := "snapshot"
			if attemptSwitch {
				runKind = "config_switch"
			}
			reportBridgeRun(ctx, base.endpoint, token, map[string]any{"run_id": runID, "kind": runKind, "status": "running", "started_at": started})
			result, err := submitSnapshotAt(ctx, targetAddr, password, sender, attemptCfg)
			completed := time.Now().UTC()
			report := map[string]any{"run_id": runID, "kind": runKind, "started_at": started, "completed_at": completed, "duration_ms": completed.Sub(started).Milliseconds(), "records_read": result.members, "records_emitted": result.records, "records_skipped": result.skipped}
			if err != nil {
				report["status"], report["error_type"] = "failed", errorType(err)
				reportBridgeRun(ctx, base.endpoint, token, report)
				state.mu.RLock()
				hasActiveSnapshot := !state.lastSnapshotAt.IsZero()
				state.mu.RUnlock()
				if attemptSwitch && hasActiveSnapshot {
					markSwitchFailure(state, err)
				} else {
					markSnapshotFailure(state, err)
				}
				if attemptSwitch {
					nextSwitchAttempt = time.Now().Add(30 * time.Second)
				} else {
					nextActiveSnapshot = time.Now().Add(10 * time.Second)
				}
			} else {
				report["status"] = "completed"
				reportBridgeRun(ctx, base.endpoint, token, report)
				activeAddr, activeVersion = targetAddr, targetVersion
				markSnapshotSuccess(state, targetAddr, targetVersion, result)
				nextActiveSnapshot = time.Now().Add(attemptCfg.reconcile)
				if attemptSwitch {
					nextSwitchAttempt = nextActiveSnapshot
				}
				logStatus("snapshot_committed", map[string]any{"source": base.source, "records": result.records})
			}
		}
		if !waitContext(ctx, time.Second) {
			return
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
		markEventHealthy(state)
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
	state.mu.Unlock()
	markEventHealthy(state)
	updateQueueMetrics(ctx, client, cfg, state)
	return true, nil
}

type snapshotResult struct {
	observedAt time.Time
	instanceID string
	members    int
	records    int
	skipped    int
}

func submitSnapshotAt(ctx context.Context, addr, password string, sender legacy4k.Sender, cfg config) (snapshotResult, error) {
	result := snapshotResult{}
	raw := redis.NewClient(&redis.Options{Addr: addr, Password: password, ReadTimeout: 8 * time.Second, WriteTimeout: 5 * time.Second})
	defer raw.Close()
	if err := raw.Ping(ctx).Err(); err != nil {
		return result, err
	}
	info, err := raw.Info(ctx, "server").Result()
	if err != nil {
		return result, err
	}
	result.instanceID = runID(info)
	if result.instanceID == "" {
		return result, fmt.Errorf("online Redis instance id unavailable")
	}
	members, err := raw.LLen(ctx, cfg.onlineList).Result()
	if err != nil {
		return result, err
	}
	result.members = int(members)
	client := legacy4k.NewRedisOnlineClient(&redis.Options{Addr: addr, Password: password, ReadTimeout: 8 * time.Second, WriteTimeout: 5 * time.Second})
	defer client.Close()
	inventory, err := legacy4k.ReadOnlineInventoryStabilized(ctx, client, cfg.onlineList, cfg.maxRecords, 500, 3)
	if err != nil {
		return result, err
	}
	stats, err := inventory.Stats()
	if err != nil {
		return result, err
	}
	result.records = stats.AddressRecords
	result.skipped = inventory.SkippedInvalid
	result.observedAt = inventory.ObservedAt
	if err = sender.SendSnapshot(ctx, inventory, cfg.source, cfg.campus, cfg.domain, int(cfg.reconcile/time.Second)); err != nil {
		return result, err
	}
	if stats.Sessions != len(inventory.Rows) {
		return result, fmt.Errorf("snapshot session acknowledgement mismatch")
	}
	return result, nil
}

func fetchBridgeRuntimeConfig(ctx context.Context, endpoint, token string) (bridgeRuntimeConfig, error) {
	var value bridgeRuntimeConfig
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/api/v1/integrations/identity/bridge/runtime-config", nil)
	if err != nil {
		return value, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return value, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return value, fmt.Errorf("identity bridge config endpoint returned %s", response.Status)
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&value); err != nil {
		return value, err
	}
	if value.ConfigVersion < 1 || value.Host == "" || value.OnlineRedisAddr == "" || value.ReconcileIntervalSeconds < 60 || value.ReconcileIntervalSeconds > 86400 {
		return bridgeRuntimeConfig{}, fmt.Errorf("identity bridge config is invalid")
	}
	return value, nil
}

func reportBridgeRun(ctx context.Context, endpoint, token string, value map[string]any) {
	body, err := json.Marshal(value)
	if err != nil {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/api/v1/integrations/identity/bridge/runs", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err == nil {
		response.Body.Close()
	}
}

func runHeartbeatWorker(ctx context.Context, cfg config, token string, state *runtimeState) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		sendBridgeHeartbeat(ctx, cfg, token, state)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sendBridgeHeartbeat(ctx context.Context, cfg config, token string, state *runtimeState) {
	state.mu.RLock()
	overall := deriveOverallState(state, cfg.reconcile)
	body, _ := json.Marshal(map[string]any{
		"active_host": state.activeHost, "active_config_version": state.activeConfigVersion, "state": overall,
		"online_channel_state": state.onlineChannelState, "event_channel_state": state.eventChannelState,
		"snapshot_state": state.snapshotState, "source_queue": state.sourceQueue, "processing_queue": state.processingQueue,
		"online_members": state.onlineMembers, "online_sessions": state.onlineSessions,
		"committed_messages": state.committedMessages, "bad_messages": state.badMessages,
		"event_consecutive_failures": state.eventConsecutiveFailures, "snapshot_consecutive_failures": state.snapshotConsecutiveFailures,
		"last_event_at": optionalTime(state.lastEventAt), "last_snapshot_attempt_at": optionalTime(state.lastSnapshotAttemptAt),
		"last_snapshot_at": optionalTime(state.lastSnapshotAt), "last_error_type": state.lastErrorType, "started_at": state.startedAt,
	})
	state.mu.RUnlock()
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, strings.TrimRight(cfg.endpoint, "/")+"/api/v1/integrations/identity/bridge/heartbeat", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err == nil {
		response.Body.Close()
	}
}

func optionalTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func startHealthServer(addr string, state *runtimeState) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		state.mu.RLock()
		ready := state.eventConsecutiveFailures < 5 && !state.lastSnapshotAt.IsZero() && time.Since(state.lastSnapshotAt) <= 90*time.Minute
		body := map[string]any{"ready": ready, "state": deriveOverallState(state, 30*time.Minute), "source_queue": state.sourceQueue, "processing_queue": state.processingQueue, "online_sessions": state.onlineSessions, "online_members": state.onlineMembers, "invalid_online_rows": state.invalidOnlineRows, "last_event_at": state.lastEventAt, "last_snapshot_attempt_at": state.lastSnapshotAttemptAt, "last_snapshot_at": state.lastSnapshotAt, "event_consecutive_failures": state.eventConsecutiveFailures, "snapshot_consecutive_failures": state.snapshotConsecutiveFailures}
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
		fmt.Fprintf(w, "proxy_sentinel_ncu_auth_source_queue %d\nproxy_sentinel_ncu_auth_processing_queue %d\nproxy_sentinel_ncu_auth_bad_messages_total %d\nproxy_sentinel_ncu_auth_committed_messages_total %d\nproxy_sentinel_ncu_auth_online_members %d\nproxy_sentinel_ncu_auth_online_sessions %d\nproxy_sentinel_ncu_auth_invalid_online_rows %d\nproxy_sentinel_ncu_auth_event_consecutive_failures %d\nproxy_sentinel_ncu_auth_snapshot_consecutive_failures %d\nproxy_sentinel_ncu_auth_snapshot_age_seconds %.0f\n", state.sourceQueue, state.processingQueue, state.badMessages, state.committedMessages, state.onlineMembers, state.onlineSessions, state.invalidOnlineRows, state.eventConsecutiveFailures, state.snapshotConsecutiveFailures, ageSeconds(state.lastSnapshotAt))
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			markEventFailure(state, err)
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

func markEventFailure(state *runtimeState, err error) {
	state.mu.Lock()
	state.lastErrorAt = time.Now().UTC()
	state.lastErrorType = errorType(err)
	state.eventConsecutiveFailures++
	state.eventChannelState = "failed"
	state.overallState = "degraded"
	state.mu.Unlock()
	logStatus("operation_failed", map[string]any{"error_type": errorType(err)})
}

func markEventHealthy(state *runtimeState) {
	state.mu.Lock()
	state.eventConsecutiveFailures = 0
	state.eventChannelState = "healthy"
	if state.snapshotState == "healthy" && state.overallState != "switching" && state.overallState != "switch_failed" {
		state.overallState = "healthy"
		state.lastErrorType = ""
	}
	state.mu.Unlock()
}

func markSnapshotFailure(state *runtimeState, err error) {
	state.mu.Lock()
	state.lastSnapshotAttemptAt = time.Now().UTC()
	state.lastErrorAt = state.lastSnapshotAttemptAt
	state.lastErrorType = errorType(err)
	state.snapshotConsecutiveFailures++
	state.snapshotState = "failed"
	state.onlineChannelState = "failed"
	state.overallState = "degraded"
	state.mu.Unlock()
	logStatus("snapshot_failed", map[string]any{"error_type": errorType(err)})
}

func markSwitchFailure(state *runtimeState, err error) {
	state.mu.Lock()
	state.lastSnapshotAttemptAt = time.Now().UTC()
	state.lastErrorAt = state.lastSnapshotAttemptAt
	state.lastErrorType = errorType(err)
	state.overallState = "switch_failed"
	state.mu.Unlock()
	logStatus("config_switch_failed", map[string]any{"error_type": errorType(err)})
}

func markSnapshotSuccess(state *runtimeState, addr string, version int64, result snapshotResult) {
	host, _, _ := net.SplitHostPort(addr)
	state.mu.Lock()
	state.activeHost = host
	state.activeConfigVersion = version
	state.instanceID = result.instanceID
	state.lastSnapshotAttemptAt = time.Now().UTC()
	state.lastSnapshotAt = result.observedAt
	state.onlineMembers = int64(result.members)
	state.onlineSessions = result.members - result.skipped
	state.invalidOnlineRows = result.skipped
	state.snapshotConsecutiveFailures = 0
	state.snapshotState = "healthy"
	state.onlineChannelState = "healthy"
	if state.eventConsecutiveFailures == 0 {
		state.overallState = "healthy"
		state.lastErrorType = ""
	} else {
		state.overallState = "degraded"
	}
	state.mu.Unlock()
}

func deriveOverallState(state *runtimeState, reconcile time.Duration) string {
	if state.eventConsecutiveFailures >= 5 || state.lastSnapshotAt.IsZero() {
		return "failed"
	}
	if time.Since(state.lastSnapshotAt) > 3*reconcile || state.snapshotConsecutiveFailures >= 5 {
		return "degraded"
	}
	if state.overallState == "switching" || state.overallState == "switch_failed" {
		return state.overallState
	}
	return "healthy"
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
