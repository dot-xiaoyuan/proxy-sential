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
	"proxy-sentinel/internal/identityprotocol"
	"proxy-sentinel/internal/legacy4k"
)

type config struct {
	durableEvents                  bool
	onlineAddr, onlinePasswordFile string
	eventAddr, eventPasswordFile   string
	catalogAddr                    string
	eventList, onlineList          string
	endpoint, tokenFile            string
	source, sensor, campus, domain string
	processingList, deadList       string
	healthAddr                     string
	batchSize, maxRecords          int
	reconcile                      time.Duration
	catalogPort                    int
	catalogPasswordFile            string
	catalogInterval                time.Duration
	restoreProcessing              bool
}

type runtimeState struct {
	quarantineQueue             int64
	queueSampledAt              time.Time
	queueSampleError            bool
	mu                          sync.RWMutex
	startedAt                   time.Time
	lastEventAt                 time.Time
	lastSnapshotAttemptAt       time.Time
	lastSnapshotAt              time.Time
	lastErrorAt                 time.Time
	lastErrorType               string
	activeHost                  string
	activeConfigVersion         int64
	activeEventAddr             string
	activeEventList             string
	activeProcessingList        string
	activeDeadList              string
	activeCatalogRedisAddr      string
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
	catalogState                string
	lastCatalogAt               time.Time
	catalogProducts             int
	catalogControls             int
	catalogErrorType            string
}

type bridgeRuntimeConfig struct {
	Host                     string `json:"host"`
	ConfigVersion            int64  `json:"config_version"`
	OnlineRedisAddr          string `json:"online_redis_addr"`
	CatalogRedisAddr         string `json:"catalog_redis_addr"`
	EventRedisAddr           string `json:"event_redis_addr"`
	OnlineList               string `json:"online_list"`
	EventList                string `json:"event_list"`
	ProcessingList           string `json:"processing_list"`
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eventPassword, err := readSecret(cfg.eventPasswordFile, true)
	if err != nil {
		return fmt.Errorf("read notification Redis credential: %w", err)
	}
	if cfg.restoreProcessing {
		eventClient := redis.NewClient(&redis.Options{Addr: cfg.eventAddr, Password: eventPassword, ReadTimeout: 35 * time.Second, WriteTimeout: 5 * time.Second})
		defer eventClient.Close()
		if err = eventClient.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("notification Redis unavailable: %w", err)
		}
		return restoreProcessing(ctx, eventClient, cfg.eventList, cfg.processingList)
	}
	onlinePassword, err := readSecret(cfg.onlinePasswordFile, true)
	if err != nil {
		return fmt.Errorf("read online Redis credential: %w", err)
	}
	catalogPassword, err := readSecret(cfg.catalogPasswordFile, true)
	if err != nil {
		return fmt.Errorf("read catalog Redis credential: %w", err)
	}
	token, err := readSecret(cfg.tokenFile, true)
	if err != nil {
		return fmt.Errorf("read identity token: %w", err)
	}
	if remote, fetchErr := fetchBridgeRuntimeConfig(ctx, cfg.endpoint, token); fetchErr == nil {
		if (remote.EventRedisAddr != "" && remote.EventRedisAddr != cfg.eventAddr) || (remote.EventList != "" && remote.EventList != cfg.eventList) || (remote.ProcessingList != "" && remote.ProcessingList != cfg.processingList) {
			original := redis.NewClient(&redis.Options{Addr: cfg.eventAddr, Password: eventPassword, ReadTimeout: time.Second, WriteTimeout: time.Second})
			drained, _ := eventSourceDrained(ctx, original, cfg)
			original.Close()
			if !drained {
				remote.EventRedisAddr, remote.EventList, remote.ProcessingList = cfg.eventAddr, cfg.eventList, cfg.processingList
			}
		}
		if remote.OnlineRedisAddr != "" {
			cfg.onlineAddr = remote.OnlineRedisAddr
		}
		if remote.CatalogRedisAddr != "" {
			cfg.catalogAddr = remote.CatalogRedisAddr
		}
		if remote.EventRedisAddr != "" {
			cfg.eventAddr = remote.EventRedisAddr
		}
		if remote.OnlineList != "" {
			cfg.onlineList = remote.OnlineList
		}
		if remote.EventList != "" {
			cfg.eventList = remote.EventList
		}
		cfg.processingList = remote.ProcessingList
		cfg.deadList = cfg.eventList + ":proxy-sentinel-dead-meta"
	}
	eventClient := redis.NewClient(&redis.Options{Addr: cfg.eventAddr, Password: eventPassword, ReadTimeout: 35 * time.Second, WriteTimeout: 5 * time.Second})
	defer eventClient.Close()
	if err = eventClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("notification Redis unavailable: %w", err)
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
	sender := legacy4k.Sender{Endpoint: cfg.endpoint, Token: token, SensorID: cfg.sensor, Source: cfg.source, CampusID: cfg.campus, AccessDomain: cfg.domain, Durable: cfg.durableEvents}
	activeHost, _, _ := net.SplitHostPort(cfg.onlineAddr)
	state := &runtimeState{activeEventAddr: cfg.eventAddr, activeEventList: cfg.eventList, activeProcessingList: cfg.processingList, activeDeadList: cfg.deadList, startedAt: time.Now().UTC(), activeHost: activeHost, activeCatalogRedisAddr: cfg.catalogAddr, instanceID: instanceID, overallState: "starting", onlineChannelState: "healthy", eventChannelState: "healthy", snapshotState: "pending"}
	server := startHealthServer(cfg.healthAddr, state)
	defer server.Shutdown(context.Background())
	logStatus("starting", map[string]any{"source": cfg.source, "sensor_id": cfg.sensor, "event_list": cfg.eventList})

	var workers sync.WaitGroup
	workers.Add(5)
	go func() { defer workers.Done(); runQueueSampler(ctx, cfg, eventPassword, token, state) }()
	go func() {
		defer workers.Done()
		runCatalogWorker(ctx, cfg, catalogPassword, token, state)
	}()
	go func() {
		defer workers.Done()
		runEventWorker(ctx, eventClient, eventPassword, sender, cfg, token, state)
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

func runEventWorker(ctx context.Context, client *redis.Client, password string, sender legacy4k.Sender, cfg config, token string, state *runtimeState) {
	activeClient, activeCfg, activeAddr := client, cfg, cfg.eventAddr
	defer func() {
		if activeClient != client {
			_ = activeClient.Close()
		}
	}()
	nextConfig := time.Time{}
	for {
		if !time.Now().Before(nextConfig) {
			if remote, err := fetchBridgeRuntimeConfig(ctx, cfg.endpoint, token); err == nil {
				wantsSwitch := (remote.EventRedisAddr != "" && remote.EventRedisAddr != activeAddr) || (remote.EventList != "" && remote.EventList != activeCfg.eventList) || (remote.ProcessingList != "" && remote.ProcessingList != activeCfg.processingList)
				if wantsSwitch {
					drained, readErr := eventSourceDrained(ctx, activeClient, activeCfg)
					state.mu.RLock()
					published := state.activeConfigVersion == remote.ConfigVersion
					state.mu.RUnlock()
					if readErr != nil {
						markEventFailure(state, readErr)
					}
					if drained && published {
						candidateAddr := remote.EventRedisAddr
						if candidateAddr == "" {
							candidateAddr = activeAddr
						}
						candidate := redis.NewClient(&redis.Options{Addr: candidateAddr, Password: password, ReadTimeout: 35 * time.Second, WriteTimeout: 5 * time.Second})
						if candidate.Ping(ctx).Err() == nil {
							if activeClient != client {
								activeClient.Close()
							}
							activeClient, activeAddr = candidate, candidateAddr
							if remote.EventList != "" {
								activeCfg.eventList = remote.EventList
							}
							if remote.ProcessingList != "" {
								activeCfg.processingList = remote.ProcessingList
							}
							activeCfg.deadList = activeCfg.eventList + ":proxy-sentinel-dead-meta"
							state.mu.Lock()
							state.activeEventAddr, state.activeEventList, state.activeProcessingList, state.activeDeadList = activeAddr, activeCfg.eventList, activeCfg.processingList, activeCfg.deadList
							state.mu.Unlock()
						} else {
							candidate.Close()
						}
					}
				}
			}
			nextConfig = time.Now().Add(5 * time.Second)
		}
		state.mu.RLock()
		instanceID := state.instanceID
		state.mu.RUnlock()
		processed, err := processBatch(ctx, activeClient, sender, activeCfg, instanceID, state)
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
		markEventHealthy(state)
		if !waitContext(ctx, time.Second) {
			return
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
				state.mu.Lock()
				if desired.CatalogRedisAddr != "" {
					state.activeCatalogRedisAddr = desired.CatalogRedisAddr
				}
				state.mu.Unlock()
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
	catalogPort := 16382
	if value := os.Getenv("NCU_CATALOG_REDIS_PORT"); value != "" {
		var err error
		catalogPort, err = strconv.Atoi(value)
		if err != nil {
			return cfg, fmt.Errorf("invalid catalog Redis port")
		}
	}
	flag.IntVar(&cfg.catalogPort, "catalog-redis-port", catalogPort, "read-only product catalog port on the committed 4K host")
	flag.StringVar(&cfg.catalogPasswordFile, "catalog-redis-password-file", os.Getenv("NCU_CATALOG_REDIS_PASSWORD_FILE"), "catalog Redis secret file; defaults to the online Redis credential")
	flag.DurationVar(&cfg.catalogInterval, "catalog-reconcile-interval", 6*time.Hour, "read-only catalog calibration interval")
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
	flag.BoolVar(&cfg.durableEvents, "durable-events", false, "require versioned durable inbox receipts")
	flag.BoolVar(&cfg.restoreProcessing, "restore-processing", false, "move unacknowledged processing messages back before the source FIFO and exit")
	flag.Parse()
	if cfg.catalogPasswordFile == "" {
		cfg.catalogPasswordFile = cfg.onlinePasswordFile
	}
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
	if cfg.catalogPort < 1 || cfg.catalogPort > 65535 || cfg.catalogInterval < time.Hour || cfg.catalogInterval > 168*time.Hour {
		return cfg, fmt.Errorf("invalid catalog port or reconciliation interval")
	}
	cfg.processingList = cfg.eventList + ":proxy-sentinel-processing"
	cfg.deadList = cfg.eventList + ":proxy-sentinel-dead-meta"
	return cfg, nil
}

func restoreProcessing(ctx context.Context, client *redis.Client, source, processing string) error {
	restored := 0
	for {
		count, err := restoreBatchScript.Run(ctx, client, []string{source, processing, processing + ":lease", processing + ":batch"}).Int()
		if err != nil {
			return err
		}
		restored += count
		if count < 1000 {
			logStatus("processing_restored", map[string]any{"restored_messages": restored})
			return nil
		}
	}
}

func processBatch(ctx context.Context, client *redis.Client, sender legacy4k.Sender, cfg config, instanceID string, state *runtimeState) (bool, error) {
	defer updateQueueMetrics(ctx, client, cfg, state)
	state.mu.RLock()
	version := state.activeConfigVersion
	state.mu.RUnlock()
	batch, err := beginReliableBatch(ctx, client, cfg, instanceID, version)
	if err != nil {
		return false, err
	}
	if batch.token != "" {
		defer releaseBatchScript.Run(ctx, client, []string{cfg.processingList + ":lease"}, batch.token)
	}
	if len(batch.Raw) == 0 {
		return false, nil
	}
	rawMessages := batch.Raw
	observedAt, err := time.Parse(time.RFC3339Nano, batch.ObservedAt)
	if err != nil {
		return true, err
	}
	sender.Source, sender.SensorID, sender.CampusID, sender.AccessDomain = batch.Source, batch.SensorID, batch.CampusID, batch.AccessDomain
	if !batch.Frozen {
		records := make([]map[string]string, 0, len(rawMessages))
		badMetadata := make([]string, 0)
		hasher := sha256.New()
		for _, raw := range rawMessages {
			hasher.Write([]byte(strconv.Itoa(len(raw))))
			hasher.Write([]byte{0})
			hasher.Write([]byte(raw))
			decoded, decodeErr := legacy4k.DecodeRecordsForInstance(raw, batch.InstanceID, observedAt)
			if decodeErr != nil {
				sum := sha256.Sum256([]byte(raw))
				meta, _ := json.Marshal(map[string]any{"sha256": hex.EncodeToString(sum[:]), "length": len(raw), "error_type": errorType(decodeErr), "observed_at": batch.ObservedAt, "raw": raw})
				badMetadata = append(badMetadata, string(meta))
				continue
			}
			records = append(records, decoded...)
		}
		hasher.Write([]byte(batch.ObservedAt + batch.InstanceID + batch.Source + batch.SensorID + batch.CampusID + batch.AccessDomain + batch.SourceVersion))
		if sender.Durable {
			hasher.Write([]byte("durable-v2"))
		}
		batchID := "legacy-4k-batch-" + hex.EncodeToString(hasher.Sum(nil))
		for _, record := range records {
			if sender.CampusID != "" {
				record["campus_id"] = sender.CampusID
			}
			if sender.AccessDomain != "" {
				record["access_domain"] = sender.AccessDomain
			}
		}
		batch.BatchID, batch.Records, batch.Quarantine, batch.Durable, batch.Frozen = batchID, records, badMetadata, sender.Durable, true
		// Persist the normalized payload too: upgrades must not reinterpret a retry.
		request := identityprotocol.Request{Source: sender.Source, SensorID: sender.SensorID, Records: records}
		batch.ContentSHA256, batch.RecordCount = request.Hash(), len(records)
		frozen, marshalErr := json.Marshal(batch)
		if marshalErr != nil {
			return true, marshalErr
		}
		if _, err = freezeBatchScript.Run(ctx, client, []string{cfg.processingList + ":lease", cfg.processingList + ":batch"}, batch.token, string(frozen)).Result(); err != nil {
			return true, err
		}
	}
	records, badMetadata, batchID := batch.Records, batch.Quarantine, batch.BatchID
	sender.Durable = batch.Durable
	request := identityprotocol.Request{Source: sender.Source, SensorID: sender.SensorID, Records: records}
	if request.Hash() != batch.ContentSHA256 || len(records) != batch.RecordCount {
		return true, fmt.Errorf("persisted batch checksum mismatch")
	}

	if err = sender.Send(ctx, records, batchID); err != nil {
		return true, err
	}
	args := []any{batch.token}
	for _, metadata := range badMetadata {
		args = append(args, metadata)
	}
	_, err = finishBatchScript.Run(ctx, client, []string{cfg.processingList, cfg.processingList + ":lease", cfg.processingList + ":batch", cfg.deadList + ":quarantine"}, args...).Result()
	if err != nil {
		return true, err
	}
	state.mu.Lock()
	state.committedMessages += uint64(len(rawMessages) - len(badMetadata))
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
	if value.ConfigVersion < 1 || value.Host == "" || value.OnlineRedisAddr == "" || value.EventRedisAddr == "" || value.EventList == "" || value.ReconcileIntervalSeconds < 60 || value.ReconcileIntervalSeconds > 86400 {
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
		"queue_sampled_at": optionalTime(state.queueSampledAt), "queue_sample_error": state.queueSampleError, "quarantine_queue": state.quarantineQueue,
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
		body := map[string]any{"ready": ready, "state": deriveOverallState(state, 30*time.Minute), "source_queue": state.sourceQueue, "processing_queue": state.processingQueue, "online_sessions": state.onlineSessions, "online_members": state.onlineMembers, "invalid_online_rows": state.invalidOnlineRows, "last_event_at": state.lastEventAt, "last_snapshot_attempt_at": state.lastSnapshotAttemptAt, "last_snapshot_at": state.lastSnapshotAt, "event_consecutive_failures": state.eventConsecutiveFailures, "snapshot_consecutive_failures": state.snapshotConsecutiveFailures, "catalog_state": state.catalogState, "last_catalog_at": optionalTime(state.lastCatalogAt), "catalog_products": state.catalogProducts, "catalog_controls": state.catalogControls, "catalog_error_type": state.catalogErrorType}
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
		pipe.LLen(ctx, cfg.deadList+":quarantine")
		return nil
	})
	if err != nil || len(values) != 3 {
		state.mu.Lock()
		state.queueSampleError = true
		state.mu.Unlock()
		return
	}
	source, sourceErr := values[0].(*redis.IntCmd).Result()
	processing, processingErr := values[1].(*redis.IntCmd).Result()
	quarantine, quarantineErr := values[2].(*redis.IntCmd).Result()
	if sourceErr == nil && processingErr == nil && quarantineErr == nil {
		state.mu.Lock()
		state.sourceQueue, state.processingQueue, state.quarantineQueue = source, processing, quarantine
		state.queueSampledAt = time.Now().UTC()
		state.queueSampleError = false
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
	if state.activeHost != host || state.activeConfigVersion != version {
		state.catalogState, state.catalogErrorType = "pending", ""
		state.lastCatalogAt = time.Time{}
		state.catalogProducts, state.catalogControls = 0, 0
	}
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
	if state.queueSampleError || state.queueSampledAt.IsZero() || time.Since(state.queueSampledAt) > 15*time.Second || time.Since(state.lastSnapshotAt) > 3*reconcile || state.snapshotConsecutiveFailures > 0 || state.eventConsecutiveFailures > 0 || state.eventChannelState == "failed" || state.onlineChannelState == "failed" || state.catalogState == "failed" || state.quarantineQueue > 0 {
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
	message := err.Error()
	for _, status := range []string{"400", "401", "403", "404", "409", "413", "422", "429", "500", "503"} {
		if strings.Contains(message, "endpoint returned "+status) {
			return "remote_http_" + status
		}
	}
	if strings.Contains(message, "acknowledgement") {
		return "acknowledgement_mismatch"
	}
	if strings.Contains(message, "snapshot calibration failed") {
		return "calibration_failed"
	}
	if strings.HasPrefix(message, "online record ") || strings.HasPrefix(message, "duplicate online session") {
		return "invalid_online_identity"
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
