package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"proxy-sentinel/internal/adapter/identity"
	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/appdomain"
	"proxy-sentinel/internal/controlplane"
	"proxy-sentinel/internal/devicesignal"
	"proxy-sentinel/internal/evaluation"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/materialize"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/replay"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/shadow"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/validation"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return usageError()
	}

	// Every processing command uses the same installed offline library.
	if dir := os.Getenv("PROXY_SENTINEL_DEVICE_FINGERPRINT_DIR"); dir != "" {
		fingerprint.NewManager(dir).SetOffline(true)
	}
	switch args[0] {
	case "adapter":
		return runAdapter(args[1:])
	case "replay":
		return runReplay(args[1:])
	case "evidence":
		return runEvidence(args[1:])
	case "risk":
		return runRisk(args[1:])
	case "shadow":
		return runShadow(args[1:])
	case "ingest":
		return runIngest(args[1:])
	case "read-model":
		return runReadModel(args[1:])
	case "control-plane":
		return runControlPlane(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "evaluate":
		return runEvaluate(args[1:])
	case "backfill":
		return runBackfill(args[1:])
	case "device-fingerprint":
		return runDeviceFingerprint(args[1:])
	case "device-signal":
		return runDeviceSignal(args[1:])
	case "router":
		return runRouter(args[1:])
	case "application-library":
		return runApplicationLibrary(args[1:])
	case "migrate":
		return runMigrate(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "-h", "--help", "help":
		return usageError()
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func runApplicationLibrary(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: proxy-sentinel application-library install --dir DIR --input FILE | rollback --dir DIR --version VERSION | status --dir DIR")
	}
	command := args[0]
	fs := flag.NewFlagSet("application-library "+command, flag.ContinueOnError)
	dir := fs.String("dir", "", "application library directory")
	input := fs.String("input", "", "reviewed application bundle")
	targetVersion := fs.String("version", "", "retained application version")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*dir) == "" {
		return fmt.Errorf("--dir is required")
	}
	manager, err := appdomain.OpenManager(*dir)
	if err != nil {
		return err
	}
	switch command {
	case "install":
		if strings.TrimSpace(*input) == "" {
			return fmt.Errorf("--input is required")
		}
		raw, readErr := os.ReadFile(*input)
		if readErr != nil {
			return readErr
		}
		if err = manager.Import(raw); err != nil {
			return err
		}
	case "rollback":
		if strings.TrimSpace(*targetVersion) == "" {
			return fmt.Errorf("--version is required")
		}
		if err = manager.Rollback(*targetVersion); err != nil {
			return err
		}
	case "status":
	default:
		return fmt.Errorf("unsupported application-library command %q", command)
	}
	return writeJSON(os.Stdout, manager.Status())
}

func runReadModel(args []string) error {
	if len(args) < 1 || args[0] != "run" {
		return fmt.Errorf("usage: proxy-sentinel read-model run --lane realtime|coarse|recognition|application --postgres-dsn <dsn> --clickhouse-dsn <dsn>")
	}
	fs := flag.NewFlagSet("read-model run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	lane := fs.String("lane", "", "worker lane: realtime, coarse, recognition, or application")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	applicationsDir := fs.String("applications-dir", "/opt/proxy-sentinel/data/applications", "durable application library directory")
	applicationsBootstrap := fs.String("applications-bootstrap", "", "optional reviewed bootstrap application bundle used only when the library is empty")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *lane != "realtime" && *lane != "coarse" && *lane != "recognition" && *lane != "application" {
		return fmt.Errorf("--lane must be realtime, coarse, recognition, or application")
	}
	if strings.TrimSpace(*postgresDSN) == "" || strings.TrimSpace(*clickhouseDSN) == "" {
		return fmt.Errorf("--postgres-dsn and --clickhouse-dsn are required")
	}
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, SensorID: *sensorID, CollectorKind: "read-model-" + *lane, PostgresDSN: *postgresDSN, ClickHouseDSN: *clickhouseDSN, RequestTimeout: 70 * time.Second})
	if err != nil {
		return err
	}
	defer backend.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch *lane {
	case "realtime":
		backend.RunRealtimeReadModels(ctx)
	case "coarse":
		backend.RunActivityV3Coarse(ctx)
	case "recognition":
		backend.RunRecognitionMaterializer(ctx)
	case "application":
		service, openErr := appdomain.OpenServiceWithDefault(*applicationsDir, backend, true)
		if openErr != nil {
			return openErr
		}
		configPath := filepath.Join(*applicationsDir, "config.json")
		if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
			config := service.Status().Config
			config.Enabled = true
			if config.HistoryIntervalMS == 0 {
				config.HistoryIntervalMS = 5000
			}
			if configureErr := service.Configure(config); configureErr != nil {
				return configureErr
			}
		}
		if service.Library.Status().Version == "" && strings.TrimSpace(*applicationsBootstrap) != "" {
			raw, readErr := os.ReadFile(*applicationsBootstrap)
			if readErr != nil {
				return fmt.Errorf("read application bootstrap bundle: %w", readErr)
			}
			if importErr := service.ChangeLibrary(raw, ""); importErr != nil {
				return fmt.Errorf("install application bootstrap bundle: %w", importErr)
			}
		}
		service.Run(ctx)
	}
	return nil
}

func runRouter(args []string) error {
	if len(args) < 1 || args[0] != "sample" {
		return fmt.Errorf("usage: proxy-sentinel router sample --interface <name> --duration 5m --work-dir <path>")
	}
	fs := flag.NewFlagSet("router sample", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	interfaceName := fs.String("interface", "", "mirror interface to observe")
	duration := fs.Duration("duration", 5*time.Minute, "capture duration")
	workDir := fs.String("work-dir", "", "independent output directory")
	sensorID := fs.String("sensor-id", "router-sample", "sensor identifier")
	zeekName := fs.String("zeek-bin", "zeek", "Zeek executable")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*interfaceName) == "" || strings.TrimSpace(*workDir) == "" {
		return fmt.Errorf("--interface and --work-dir are required")
	}
	if *duration <= 0 || *duration > 24*time.Hour {
		return fmt.Errorf("--duration must be greater than zero and at most 24h")
	}
	zeekBinary, err := exec.LookPath(*zeekName)
	if err != nil {
		return fmt.Errorf("find zeek executable: %w", err)
	}
	runDir := filepath.Join(*workDir, "router-sample-"+time.Now().UTC().Format("20060102T150405Z"))
	zeekDir := filepath.Join(runDir, "zeek")
	if err := os.MkdirAll(zeekDir, 0o750); err != nil {
		return err
	}
	command := exec.Command(zeekBinary, "-i", *interfaceName, "LogAscii::use_json=T")
	command.Dir = zeekDir
	command.Stdout, command.Stderr = os.Stderr, os.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start zeek capture: %w", err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	captureContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	timer := time.NewTimer(*duration)
	defer timer.Stop()
	exited := false
	select {
	case err := <-wait:
		exited = true
		if err != nil {
			return fmt.Errorf("zeek capture stopped unexpectedly: %w", err)
		}
	case <-timer.C:
		_ = command.Process.Signal(os.Interrupt)
	case <-captureContext.Done():
		_ = command.Process.Signal(os.Interrupt)
	}
	if !exited {
		select {
		case <-wait:
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			<-wait
		}
	}
	emptyEVE := filepath.Join(runDir, "empty-eve.json")
	if err := os.WriteFile(emptyEVE, nil, 0o640); err != nil {
		return err
	}
	zeekLogs := map[string]string{}
	for _, kind := range []string{"dhcp", "software", "conn", "dns", "http", "ssl", "x509", "mdns", "nbns", "llmnr", "lldp", "ssdp", "ttl"} {
		path := filepath.Join(zeekDir, kind+".log")
		if _, statErr := os.Stat(path); statErr == nil {
			zeekLogs[kind] = path
		}
	}
	summary, err := shadow.Run(shadow.Options{EVEPath: emptyEVE, ZeekLogs: zeekLogs, StatePath: filepath.Join(runDir, "state.json"), OutDir: filepath.Join(runDir, "shadow"), SensorID: *sensorID, Window: 10 * time.Minute, StorageMode: "file"})
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, map[string]any{"mode": "sample_only", "shadow_mode": true, "interface": *interfaceName, "duration": duration.String(), "work_dir": runDir, "zeek_logs": zeekLogs, "router_candidates": summary.RouterAssessmentCount, "router_evidence": summary.RouterEvidenceCount, "source_distribution": summary.RouterSourceDistribution, "shadow_run": summary})
}

func runIngest(args []string) error {
	if len(args) < 1 || args[0] != "run" {
		return fmt.Errorf("usage: proxy-sentinel ingest run --eve <path> --postgres-dsn <dsn> --clickhouse-dsn <dsn>")
	}
	fs := flag.NewFlagSet("ingest run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	proxyConfigFile := fs.String("proxy-protocol-config", "", "trusted proxy producer registration file")
	zeekProxy := fs.String("zeek-proxy", "", "Zeek proxy_transactions.log path")
	scopeFile := fs.String("capture-scope-config", "", "controlled capture scope and validity interval")
	collectorInstanceID := fs.String("collector-instance-id", "", "Suricata boot identifier; change on collector restart")
	evePath := fs.String("eve", "", "Suricata EVE JSON path")
	zeekDHCP := fs.String("zeek-dhcp", "", "Zeek DHCP log path")
	zeekSoftware := fs.String("zeek-software", "", "Zeek software log path")
	zeekMDNS := fs.String("zeek-mdns", "", "Zeek mDNS device-signal log path")
	zeekNBNS := fs.String("zeek-nbns", "", "Zeek NBNS device-signal log path")
	zeekLLMNR := fs.String("zeek-llmnr", "", "Zeek LLMNR device-signal log path")
	zeekTTL := fs.String("zeek-ttl", "", "Zeek TTL device-signal log path")
	zeekConn := fs.String("zeek-conn", "", "Zeek conn.log path")
	zeekDNS := fs.String("zeek-dns", "", "Zeek dns.log path")
	zeekHTTP := fs.String("zeek-http", "", "Zeek http.log path")
	zeekSSL := fs.String("zeek-ssl", "", "Zeek ssl.log path")
	zeekX509 := fs.String("zeek-x509", "", "Zeek x509.log path")
	zeekLLDP := fs.String("zeek-lldp", "", "Zeek lldp.log path")
	zeekSSDP := fs.String("zeek-ssdp", "", "Zeek ssdp.log path")
	deviceSignals := fs.String("device-signals", "", "normalized TTL/device signal JSONL path")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	interval := fs.Duration("poll-interval", 5*time.Second, "source polling interval")
	maxBatchBytes := fs.Int64("max-batch-bytes", 8<<20, "maximum source bytes per committed batch")
	storeTimeout := fs.Duration("store-timeout", 2*time.Minute, "storage operation timeout")
	heartbeat := fs.Duration("heartbeat-interval", 30*time.Second, "source heartbeat interval")
	alertLagBytes := fs.Int64("alert-lag-bytes", 64<<20, "webhook threshold for source lag bytes")
	alertBadRate := fs.Float64("alert-bad-line-rate", 0.01, "webhook threshold for malformed line ratio")
	alertWebhook := fs.String("alert-webhook", os.Getenv("PROXY_SENTINEL_INGEST_ALERT_WEBHOOK"), "optional generic ingest alert webhook")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *postgresDSN == "" || *clickhouseDSN == "" {
		return fmt.Errorf("--postgres-dsn and --clickhouse-dsn are required")
	}
	captureScope, err := normalized.LoadCaptureScope(*scopeFile)
	if err != nil {
		return err
	}
	proxyConfig, err := proxyprotocol.Load(*proxyConfigFile)
	if err != nil {
		return err
	}
	sources := []realtime.Source{}
	for _, source := range []realtime.Source{
		{Kind: "suricata", Path: *evePath, CollectorInstanceID: *collectorInstanceID, ProxyProducer: proxyConfig.Producer(*sensorID, "suricata", *collectorInstanceID)},
		{Kind: "zeek-proxy", Path: *zeekProxy, CollectorInstanceID: *collectorInstanceID, ProxyProducer: proxyConfig.Producer(*sensorID, "zeek", *collectorInstanceID)},
		{Kind: "zeek-dhcp", Path: *zeekDHCP},
		{Kind: "zeek-software", Path: *zeekSoftware},
		{Kind: "zeek-mdns", Path: *zeekMDNS},
		{Kind: "zeek-nbns", Path: *zeekNBNS},
		{Kind: "zeek-llmnr", Path: *zeekLLMNR},
		{Kind: "zeek-ttl", Path: *zeekTTL},
		{Kind: "zeek-conn", Path: *zeekConn},
		{Kind: "zeek-dns", Path: *zeekDNS},
		{Kind: "zeek-http", Path: *zeekHTTP},
		{Kind: "zeek-ssl", Path: *zeekSSL},
		{Kind: "zeek-x509", Path: *zeekX509},
		{Kind: "zeek-lldp", Path: *zeekLLDP},
		{Kind: "zeek-ssdp", Path: *zeekSSDP},
		{Kind: "device-signals", Path: *deviceSignals},
	} {
		if source.Path != "" {
			source.CaptureScope = captureScope
			if strings.HasPrefix(source.Kind, "zeek-") {
				source.CollectorInstanceID = *collectorInstanceID
			}
			sources = append(sources, source)
		}
	}
	if len(sources) == 0 {
		return fmt.Errorf("at least one of --eve, --zeek-dhcp or --zeek-software is required")
	}
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, SensorID: *sensorID, CollectorKind: "realtime", PostgresDSN: *postgresDSN, ClickHouseDSN: *clickhouseDSN, RequestTimeout: *storeTimeout})
	if err != nil {
		return err
	}
	defer backend.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return realtime.Run(ctx, backend, realtime.Options{SensorID: *sensorID, Sources: sources, PollInterval: *interval, MaxBatchBytes: *maxBatchBytes, StoreTimeout: *storeTimeout, AlertWebhook: *alertWebhook, Heartbeat: *heartbeat, AlertLagBytes: *alertLagBytes, AlertBadRate: *alertBadRate})
}

func runDeviceSignal(args []string) error {
	if len(args) < 1 || args[0] != "run" {
		return fmt.Errorf("usage: proxy-sentinel device-signal run --interface <name> --output <path>")
	}
	fs := flag.NewFlagSet("device-signal run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	scopeFile := fs.String("capture-scope-config", "", "controlled capture scope and validity interval")
	instanceID := fs.String("collector-instance-id", "", "packet collector process instance")
	interfaceName := fs.String("interface", "", "capture interface")
	output := fs.String("output", "", "normalized device signal JSONL output")
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	bucket := fs.Duration("bucket", 5*time.Second, "aggregation bucket")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	captureScope, err := normalized.LoadCaptureScope(*scopeFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return devicesignal.Run(ctx, devicesignal.Options{CaptureScope: captureScope, CollectorInstanceID: *instanceID, Interface: *interfaceName, Output: *output, SensorID: *sensorID, Bucket: *bucket})
}

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN (defaults to PROXY_SENTINEL_POSTGRES_DSN)")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN (defaults to PROXY_SENTINEL_CLICKHOUSE_DSN)")
	postgresDir := fs.String("postgres-dir", "migrations/postgres", "PostgreSQL migration directory")
	clickhouseDir := fs.String("clickhouse-dir", "migrations/clickhouse", "ClickHouse migration directory")
	backfill := fs.Bool("backfill-application-read-model", false, "resume bounded latest-event read-model backfill after migration")
	migrationTimeout := fs.Duration("timeout", 5*time.Minute, "migration and resumable read-model backfill deadline")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *migrationTimeout)
	defer cancel()
	postgres, err := store.ApplyPostgresMigrations(ctx, *postgresDSN, *postgresDir)
	if err != nil {
		return fmt.Errorf("PostgreSQL migration failed: %w", err)
	}
	clickhouse, err := store.ApplyClickHouseMigrations(ctx, *clickhouseDSN, *clickhouseDir)
	if err != nil {
		return fmt.Errorf("ClickHouse migration failed: %w", err)
	}
	if *backfill {
		if err := store.BackfillApplicationReadModel(ctx, *postgresDSN, *clickhouseDSN); err != nil {
			return err
		}
	}
	return writeJSON(os.Stdout, map[string]any{"postgres": postgres, "clickhouse": clickhouse})
}

func runDeviceFingerprint(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: proxy-sentinel device-fingerprint <build|verify|install>")
	}
	switch args[0] {
	case "build-embedded":
		fs := flag.NewFlagSet("device-fingerprint build-embedded", flag.ContinueOnError)
		output := fs.String("output", "", "output .tar.gz bundle")
		bundleVersion := fs.String("version", "", "bundle version")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *output == "" {
			return fmt.Errorf("--output is required")
		}
		manifest, err := fingerprint.BuildEmbeddedBundle(*output, *bundleVersion, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "embedded device fingerprint bundle built: version=%s output=%s\n", manifest.Version, *output)
		return nil
	case "build":
		fs := flag.NewFlagSet("device-fingerprint build", flag.ContinueOnError)
		output := fs.String("output", "", "output .tar.gz bundle")
		uapSHA := fs.String("uap-sha", "", "optional pinned uap-core commit SHA")
		nextDNSSHA := fs.String("nextdns-sha", "", "optional pinned NextDNS domain-list commit SHA")
		hageziSHA := fs.String("hagezi-sha", "", "optional pinned HaGeZi native tracker commit SHA")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *output == "" {
			return fmt.Errorf("--output is required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		manifest, err := fingerprint.BuildOfflineBundle(ctx, *output, fingerprint.BuildOptions{UAPSHA: *uapSHA, NextDNSSHA: *nextDNSSHA, HaGeZiSHA: *hageziSHA})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "device fingerprint bundle built: version=%s output=%s\n", manifest.Version, *output)
		return nil
	case "verify":
		fs := flag.NewFlagSet("device-fingerprint verify", flag.ContinueOnError)
		bundlePath := fs.String("bundle", "", "bundle path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *bundlePath == "" {
			return fmt.Errorf("--bundle is required")
		}
		bundle, err := fingerprint.VerifyBundleFile(*bundlePath)
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, bundle.Manifest)
	case "install":
		fs := flag.NewFlagSet("device-fingerprint install", flag.ContinueOnError)
		bundlePath := fs.String("bundle", "", "bundle path")
		dir := fs.String("dir", "", "target fingerprint directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *bundlePath == "" || *dir == "" {
			return fmt.Errorf("--bundle and --dir are required")
		}
		data, err := os.ReadFile(*bundlePath)
		if err != nil {
			return err
		}
		manager := fingerprint.NewManager(*dir)
		manager.SetOffline(true)
		status, err := manager.Import(data)
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, status)
	default:
		return fmt.Errorf("unknown device-fingerprint command: %s", args[0])
	}
}

func runBackfill(args []string) error {
	if len(args) < 1 || args[0] != "identity" {
		return fmt.Errorf("usage: proxy-sentinel backfill identity --postgres-dsn <dsn> --clickhouse-dsn <dsn> [--sensor-id office-30] [--window 7d]")
	}
	fs := flag.NewFlagSet("backfill identity", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	window := fs.String("window", "7d", "retained event window")
	limit := fs.Int("limit", 50000, "maximum normalized device events to backfill")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *postgresDSN == "" || *clickhouseDSN == "" {
		return fmt.Errorf("--postgres-dsn and --clickhouse-dsn are required")
	}
	if *limit < 1 {
		return fmt.Errorf("--limit must be greater than zero")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	clickhouseStore, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: *clickhouseDSN})
	if err != nil {
		return err
	}
	events, err := clickhouseStore.ListEventSamples(ctx, store.Query{
		Level:    "device",
		SensorID: *sensorID,
		Window:   *window,
		Limit:    *limit,
	})
	if err != nil {
		return fmt.Errorf("read retained device events: %w", err)
	}
	postgresStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: *postgresDSN, SensorID: *sensorID})
	if err != nil {
		return err
	}
	defer postgresStore.Close()
	if err := postgresStore.WriteIdentityEvents(ctx, events); err != nil {
		return fmt.Errorf("materialize retained device identities: %w", err)
	}
	state := store.BuildIdentityState(events)
	fmt.Fprintf(os.Stderr, "identity backfill: events=%d endpoints=%d ip_mac_history=%d\n", len(events), len(state.Endpoints), len(state.IPMACHistory))
	return nil
}

func runAdapter(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing adapter name")
	}

	switch args[0] {
	case "suricata":
		return runSuricataAdapter(args[1:])
	case "zeek":
		return runZeekAdapter(args[1:])
	case "identity":
		return runIdentityAdapter(args[1:])
	default:
		return fmt.Errorf("unknown adapter: %s", args[0])
	}
}

func runSuricataAdapter(args []string) error {
	fs := flag.NewFlagSet("adapter suricata", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	scopeFile := fs.String("capture-scope-config", "", "controlled capture scope and validity interval")
	input := fs.String("input", "", "Suricata EVE JSONL input path, or - for stdin")
	output := fs.String("output", "", "normalized JSONL output path, or - for stdout")
	proxyConfigFile := fs.String("proxy-protocol-config", "", "trusted proxy producer registration file")
	instanceID := fs.String("collector-instance-id", "", "collector boot identifier; required for application connection metering")
	sensorID := fs.String("sensor-id", "", "optional sensor identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	captureScope, err := normalized.LoadCaptureScope(*scopeFile)
	if err != nil {
		return err
	}
	proxyConfig, err := proxyprotocol.Load(*proxyConfigFile)
	if err != nil {
		return err
	}
	stats, err := suricata.ConvertFiles(*input, *output, suricata.Options{CaptureScope: captureScope, SensorID: *sensorID, CollectorInstanceID: *instanceID, ProxyProducer: proxyConfig.Producer(*sensorID, "suricata", *instanceID)})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "suricata adapter: read=%d emitted=%d skipped=%d malformed=%d\n", stats.Read, stats.Emitted, stats.Skipped, stats.Malformed)
	return nil
}

func runZeekAdapter(args []string) error {
	fs := flag.NewFlagSet("adapter zeek", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	scopeFile := fs.String("capture-scope-config", "", "controlled capture scope and validity interval")
	input := fs.String("input", "", "Zeek dhcp.log or software.log input path, or - for stdin")
	output := fs.String("output", "", "normalized JSONL output path, or - for stdout")
	sensorID := fs.String("sensor-id", "", "optional sensor identifier")
	proxyConfigFile := fs.String("proxy-protocol-config", "", "trusted proxy producer registration file")
	instanceID := fs.String("collector-instance-id", "", "collector boot identifier")
	logKind := fs.String("log-kind", "", "optional dhcp, software, conn, dns, http, ssl, x509, lldp, ssdp, mdns, nbns, llmnr or ttl log kind")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	captureScope, err := normalized.LoadCaptureScope(*scopeFile)
	if err != nil {
		return err
	}
	proxyConfig, err := proxyprotocol.Load(*proxyConfigFile)
	if err != nil {
		return err
	}
	stats, err := zeek.ConvertFiles(*input, *output, zeek.Options{CaptureScope: captureScope, SensorID: *sensorID, LogKind: *logKind, CollectorInstanceID: *instanceID, ProxyProducer: proxyConfig.Producer(*sensorID, "zeek", *instanceID)})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "zeek adapter: read=%d emitted=%d skipped=%d malformed=%d\n", stats.Read, stats.Emitted, stats.Skipped, stats.Malformed)
	return nil
}

func runIdentityAdapter(args []string) error {
	fs := flag.NewFlagSet("adapter identity", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "identity JSONL/CSV input path, or - for stdin")
	output := fs.String("output", "", "normalized JSONL output path, or - for stdout")
	sensorID := fs.String("sensor-id", "", "optional sensor identifier")
	source := fs.String("source", "", "identity source name, for example radius, portal, dot1x, dhcp, switch, ac")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	in, closeInput, err := openInput(*input)
	if err != nil {
		return err
	}
	defer closeInput()
	out, closeOutput, err := openOutput(*output)
	if err != nil {
		return err
	}
	defer closeOutput()
	stats, err := identity.Convert(in, out, identity.Options{SensorID: *sensorID, Source: *source})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "identity adapter: read=%d emitted=%d skipped=%d malformed=%d\n", stats.Read, stats.Emitted, stats.Skipped, stats.Malformed)
	return nil
}

func runReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "normalized JSONL input path, or - for stdin")
	output := fs.String("output", "-", "replay summary JSON output path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	summary, err := replay.AnalyzeFiles(*input, *output, replay.Options{})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "replay: read=%d accepted=%d duplicate=%d skipped=%d malformed=%d ips=%d\n",
		summary.Stats.Read,
		summary.Stats.Accepted,
		summary.Stats.Duplicate,
		summary.Stats.Skipped,
		summary.Stats.Malformed,
		len(summary.Windows),
	)
	return nil
}

func runEvidence(args []string) error {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "normalized JSONL input path, or - for stdin")
	output := fs.String("output", "-", "evidence JSON output path, or - for stdout")
	window := fs.Duration("window", 10*time.Minute, "evidence window, for example 10m or 1h")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	result, err := evidence.AnalyzeFiles(*input, *output, evidence.Options{Window: *window})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "evidence: read=%d accepted=%d duplicate=%d skipped=%d malformed=%d evidence=%d\n",
		result.Stats.Read,
		result.Stats.Accepted,
		result.Stats.Duplicate,
		result.Stats.Skipped,
		result.Stats.Malformed,
		len(result.Evidence),
	)
	return nil
}

func runRisk(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing risk command")
	}
	switch args[0] {
	case "inspect":
		return runRiskInspect(args[1:])
	case "batch":
		return runRiskBatch(args[1:])
	case "list":
		return runRiskList(args[1:])
	case "recalculate":
		return runRiskRecalculate(args[1:])
	case "materialize":
		return runRiskMaterialize(args[1:])
	default:
		return fmt.Errorf("unknown risk command: %s", args[0])
	}
}

func runRiskMaterialize(args []string) error {
	fs := flag.NewFlagSet("risk materialize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	window := fs.Duration("window", 10*time.Minute, "rolling evidence window")
	interval := fs.Duration("interval", time.Minute, "materialization interval")
	limit := fs.Int("event-limit", 200000, "maximum events per rolling window")
	sharedAccess := fs.Bool("shared-access", os.Getenv("PROXY_SENTINEL_SHARED_ACCESS_ENABLED") == "true", "build scoped shared access evidence for observation policies")
	once := fs.Bool("once", false, "run one materialization and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *postgresDSN == "" || *clickhouseDSN == "" {
		return fmt.Errorf("--postgres-dsn and --clickhouse-dsn are required")
	}
	backend, err := store.NewDBStore(store.Options{Mode: store.ModeDB, SensorID: *sensorID, CollectorKind: "risk-materializer", PostgresDSN: *postgresDSN, ClickHouseDSN: *clickhouseDSN, RequestTimeout: 2 * time.Minute})
	if err != nil {
		return err
	}
	defer backend.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runOnce := func() error {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		result, err := materialize.RunOnce(runCtx, backend, materialize.Options{SharedAccess: *sharedAccess, SensorID: *sensorID, Window: *window, Limit: *limit})
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "risk materialize: events=%d evidence=%d snapshots=%d duration=%s\n", result.Events, result.Evidence, result.Snapshots, result.CompletedAt.Sub(result.StartedAt).Round(time.Millisecond))
		return nil
	}
	if err := runOnce(); err != nil {
		return err
	}
	if *once {
		return nil
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := runOnce(); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "risk materialize failed: %v\n", err)
			}
		}
	}
}

func runRiskRecalculate(args []string) error {
	fs := flag.NewFlagSet("risk recalculate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	postgresDSN := fs.String("postgres-dsn", "", "PostgreSQL DSN")
	window := fs.Duration("window", 7*24*time.Hour, "evidence window to recalculate")
	rulesetVersion := fs.String("ruleset-version", "university-v2", "new risk ruleset version")
	apply := fs.Bool("apply", false, "persist recalculated snapshots after archiving the current snapshots")
	output := fs.String("output", "-", "comparison report path or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *postgresDSN == "" {
		return fmt.Errorf("--postgres-dsn is required")
	}
	postgres, err := store.NewPostgresStore(store.PostgresOptions{DSN: *postgresDSN})
	if err != nil {
		return err
	}
	defer postgres.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	report, err := postgres.RecalculateRisks(ctx, *window, *rulesetVersion, *apply)
	if err != nil {
		return err
	}
	file, closeOutput, err := openOutput(*output)
	if err != nil {
		return err
	}
	defer closeOutput()
	if err := writeJSON(file, report); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "risk recalculate: evidence=%d snapshots=%d changed=%d applied=%t\n", report.EvidenceCount, report.RecalculatedCount, report.ChangedCount, report.Applied)
	return nil
}

func runRiskInspect(args []string) error {
	fs := flag.NewFlagSet("risk inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "evidence JSON input path, or - for stdin")
	ip := fs.String("ip", "", "IP address to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *ip == "" {
		return fmt.Errorf("--ip is required")
	}

	snapshot, err := risk.InspectFile(*input, risk.InspectOptions{IP: *ip})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "risk inspect: ip=%s score=%d level=%s evidence=%d\n", snapshot.IP, snapshot.Score, snapshot.Level, len(snapshot.EvidenceIDs))
	return writeJSON(os.Stdout, snapshot)
}

func runRiskBatch(args []string) error {
	fs := flag.NewFlagSet("risk batch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "evidence JSON input path, or - for stdin")
	output := fs.String("output", "", "risk snapshots JSON output path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	if *output == "" {
		return fmt.Errorf("--output is required")
	}

	result, err := risk.BatchFile(*input, *output)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "risk batch: snapshots=%d\n", len(result.Snapshots))
	return nil
}

func runRiskList(args []string) error {
	fs := flag.NewFlagSet("risk list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "risk snapshots JSON input path, or - for stdin")
	output := fs.String("output", "-", "risk list JSON output path, or - for stdout")
	minLevel := fs.String("min-level", "suspicious", "minimum risk level: normal, suspicious, high, confirmed")
	limit := fs.Int("limit", 50, "maximum snapshots to output; 0 means unlimited")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	result, err := risk.ListFile(*input, *output, risk.ListOptions{MinLevel: *minLevel, Limit: *limit})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "risk list: min_level=%s snapshots=%d\n", result.MinLevel, len(result.Snapshots))
	return nil
}

func runShadow(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing shadow command")
	}
	switch args[0] {
	case "run":
		return runShadowRun(args[1:])
	default:
		return fmt.Errorf("unknown shadow command: %s", args[0])
	}
}

func runShadowRun(args []string) error {
	fs := flag.NewFlagSet("shadow run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	collectorInstanceID := fs.String("collector-instance-id", "", "Suricata collector boot identifier for connection metering")
	eve := fs.String("eve", "/var/log/suricata/eve.json", "Suricata EVE JSONL path")
	zeekDHCP := fs.String("zeek-dhcp", "", "optional Zeek dhcp.log path to append as device events")
	zeekSoftware := fs.String("zeek-software", "", "optional Zeek software.log path to append as device events")
	zeekConn := fs.String("zeek-conn", "", "optional Zeek conn.log path")
	zeekDNS := fs.String("zeek-dns", "", "optional Zeek dns.log path")
	zeekHTTP := fs.String("zeek-http", "", "optional Zeek http.log path")
	zeekSSL := fs.String("zeek-ssl", "", "optional Zeek ssl.log path")
	zeekX509 := fs.String("zeek-x509", "", "optional Zeek x509.log path")
	zeekMDNS := fs.String("zeek-mdns", "", "optional Zeek mDNS log path")
	zeekNBNS := fs.String("zeek-nbns", "", "optional Zeek NBNS log path")
	zeekLLMNR := fs.String("zeek-llmnr", "", "optional Zeek LLMNR log path")
	zeekLLDP := fs.String("zeek-lldp", "", "optional Zeek lldp.log path")
	zeekSSDP := fs.String("zeek-ssdp", "", "optional Zeek ssdp.log path")
	zeekTTL := fs.String("zeek-ttl", "", "optional Zeek TTL signal log path")
	state := fs.String("state", "data/shadow/state.json", "shadow offset state path")
	outDir := fs.String("out-dir", "data/shadow", "shadow output directory")
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	window := fs.Duration("window", 10*time.Minute, "evidence window, for example 10m or 1h")
	minLevel := fs.String("min-level", "suspicious", "risk list minimum level")
	limit := fs.Int("limit", 50, "risk list maximum snapshots")
	retention := fs.Duration("retention", 7*24*time.Hour, "run directory retention, for example 168h")
	storageMode := fs.String("storage-mode", firstEnv("PROXY_SENTINEL_STORAGE_MODE", "file"), "storage mode: file, db, or dual")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN for production evidence/risk/audit storage")
	clickHouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP URL for production event/diagnostic storage")
	storeTimeout := fs.Duration("store-timeout", 5*time.Minute, "maximum time for persisting one shadow run")
	if err := fs.Parse(args); err != nil {
		return err
	}

	summary, err := shadow.Run(shadow.Options{
		CollectorInstanceID: *collectorInstanceID,
		EVEPath:             *eve,
		ZeekDHCPPath:        *zeekDHCP,
		ZeekSoftwarePath:    *zeekSoftware,
		ZeekLogs:            map[string]string{"conn": *zeekConn, "dns": *zeekDNS, "http": *zeekHTTP, "ssl": *zeekSSL, "x509": *zeekX509, "mdns": *zeekMDNS, "nbns": *zeekNBNS, "llmnr": *zeekLLMNR, "lldp": *zeekLLDP, "ssdp": *zeekSSDP, "ttl": *zeekTTL},
		StatePath:           *state,
		OutDir:              *outDir,
		SensorID:            *sensorID,
		Window:              *window,
		ListMinLevel:        *minLevel,
		ListLimit:           *limit,
		Retention:           *retention,
		StorageMode:         *storageMode,
		PostgresDSN:         *postgresDSN,
		ClickHouseDSN:       *clickHouseDSN,
		StoreTimeout:        *storeTimeout,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "shadow run: normalized=%d evidence=%d risks=%d list=%d run_dir=%s\n",
		summary.Normalized.Emitted,
		summary.EvidenceCount,
		summary.RiskCount,
		summary.RiskListCount,
		summary.RunDir,
	)
	return writeJSON(os.Stdout, summary)
}

func runControlPlane(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing control-plane command")
	}
	switch args[0] {
	case "serve":
		return runControlPlaneServe(args[1:])
	case "bootstrap-admin":
		return runBootstrapAdmin(args[1:])
	default:
		return fmt.Errorf("unknown control-plane command: %s", args[0])
	}
}

func runBootstrapAdmin(args []string) error {
	fs := flag.NewFlagSet("control-plane bootstrap-admin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	authFile := fs.String("auth-file", "", "local authentication file")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN for production authentication")
	username := fs.String("username", "admin", "administrator username")
	name := fs.String("name", "系统管理员", "administrator display name")
	passwordEnv := fs.String("password-env", "PROXY_SENTINEL_ADMIN_PASSWORD", "environment variable containing the initial password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*authFile == "") == (*postgresDSN == "") {
		return fmt.Errorf("exactly one of --auth-file or --postgres-dsn is required")
	}
	password := os.Getenv(*passwordEnv)
	if password == "" {
		return fmt.Errorf("%s must contain the initial password", *passwordEnv)
	}
	if *postgresDSN != "" {
		if err := controlplane.BootstrapAdminPostgres(*postgresDSN, *username, *name, password); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "local administrator created in PostgreSQL: username=%s\n", *username)
		return nil
	}
	if err := controlplane.BootstrapAdmin(*authFile, *username, *name, password); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "local administrator created: username=%s auth_file=%s\n", *username, *authFile)
	return nil
}

func runValidate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing validate command")
	}
	switch args[0] {
	case "known-devices":
		return runValidateKnownDevices(args[1:])
	default:
		return fmt.Errorf("unknown validate command: %s", args[0])
	}
}

func runEvaluate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing evaluate command")
	}
	switch args[0] {
	case "shadow":
		return runEvaluateShadow(args[1:])
	case "compare":
		return runEvaluateCompare(args[1:])
	case "routers":
		return runEvaluateRouters(args[1:])
	default:
		return fmt.Errorf("unknown evaluate command: %s", args[0])
	}
}

func runEvaluateRouters(args []string) error {
	fs := flag.NewFlagSet("evaluate routers", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	manifest := fs.String("manifest", "", "router golden manifest path")
	output := fs.String("output", "-", "router evaluation report path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" {
		return fmt.Errorf("--manifest is required")
	}
	report, err := evaluation.EvaluateRouters(*manifest)
	if err != nil {
		return err
	}
	out, closeOutput, err := openOutputWithParents(*output)
	if err != nil {
		return err
	}
	defer closeOutput()
	if err := writeJSON(out, report); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "evaluate routers: samples=%d candidate=%d likely=%d confirmed=%d precision=%.4f recall=%.4f failed=%d\n", report.TotalSamples, report.CandidateCount, report.LikelyCount, report.ConfirmedCount, report.RouterPrecision, report.RouterRecall, report.Failed)
	return nil
}

func runEvaluateCompare(args []string) error {
	fs := flag.NewFlagSet("evaluate compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	currentPath := fs.String("current", "", "current risk batch JSON")
	legacyPath := fs.String("legacy", "", "legacy JSON or CSV assessments")
	outputPath := fs.String("output", "-", "comparison report path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *currentPath == "" || *legacyPath == "" {
		return fmt.Errorf("--current and --legacy are required")
	}
	currentFile, closeCurrent, err := openInput(*currentPath)
	if err != nil {
		return err
	}
	defer closeCurrent()
	var current risk.BatchResult
	if err := json.NewDecoder(currentFile).Decode(&current); err != nil {
		return err
	}
	legacyFile, closeLegacy, err := openInput(*legacyPath)
	if err != nil {
		return err
	}
	defer closeLegacy()
	legacy, err := evaluation.ReadLegacy(legacyFile)
	if err != nil {
		return err
	}
	output, closeOutput, err := openOutput(*outputPath)
	if err != nil {
		return err
	}
	defer closeOutput()
	return json.NewEncoder(output).Encode(evaluation.Compare(current, legacy))
}

func runEvaluateShadow(args []string) error {
	fs := flag.NewFlagSet("evaluate shadow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	shadowDir := fs.String("shadow-dir", "data/shadow", "shadow run and label directory")
	fromRaw := fs.String("from", "", "optional RFC3339 or YYYY-MM-DD window start")
	toRaw := fs.String("to", "", "optional RFC3339 or YYYY-MM-DD window end")
	requiredDays := fs.Int("required-days", 7, "minimum continuous run and reviewed days")
	samplesPerDay := fs.Int("samples-per-level", 10, "daily exported samples per risk level")
	exportDir := fs.String("daily-export-dir", "", "optional directory for stratified daily review samples")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "optional PostgreSQL DSN for labels written by DB/dual control planes")
	minPrecision := fs.Float64("min-precision", 0.95, "minimum candidate precision; 0 disables the check")
	minNormalGroundTruth := fs.Int("min-normal-ground-truth", 200, "minimum reviewed normal samples; 0 disables the check")
	minCandidateReviews := fs.Int("min-candidate-reviews", 200, "minimum reviewed candidate samples; 0 disables the check")
	output := fs.String("output", "-", "evaluation report JSON path, or - for stdout")
	strict := fs.Bool("strict", false, "return an error unless the shadow evaluation is ready")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *minPrecision < 0 || *minPrecision > 1 || *minNormalGroundTruth < 0 || *minCandidateReviews < 0 {
		return fmt.Errorf("accuracy thresholds must be within [0,1] for precision and non-negative for counts")
	}
	from, err := parseEvaluationTime(*fromRaw, false)
	if err != nil {
		return fmt.Errorf("parse --from: %w", err)
	}
	to, err := parseEvaluationTime(*toRaw, true)
	if err != nil {
		return fmt.Errorf("parse --to: %w", err)
	}
	report, err := evaluation.EvaluateShadow(evaluation.ShadowOptions{
		ShadowDir: *shadowDir, From: from, To: to, RequiredDays: *requiredDays,
		SamplesPerDay: *samplesPerDay, ExportDir: *exportDir, PostgresDSN: *postgresDSN,
		MinPrecision: *minPrecision, MinNormalGroundTruth: *minNormalGroundTruth,
		MinCandidateReviews: *minCandidateReviews,
	})
	if err != nil {
		return err
	}
	out, closeOutput, err := openOutputWithParents(*output)
	if err != nil {
		return err
	}
	defer closeOutput()
	if err := writeJSON(out, report); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "evaluate shadow: ready=%t runs=%d days=%d continuous=%d reviewed_days=%d snapshots=%d reviewed=%d candidates=%d normal=%d precision=%.2f blockers=%d\n",
		report.Ready, report.RunCount, report.ObservedDays, report.LongestContinuousDays, report.DaysWithReviews,
		report.RiskSnapshotCount, report.ReviewedSnapshotCount, report.CandidateReviewed, report.NormalReviewed,
		report.CandidatePrecision, len(report.Blockers))
	if *strict && !report.Ready {
		return fmt.Errorf("shadow evaluation is not ready: %s", strings.Join(report.Blockers, "; "))
	}
	return nil
}

func parseEvaluationTime(raw string, endOfDay bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed, nil
	}
	parsed, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD")
	}
	if endOfDay {
		return parsed.Add(24*time.Hour - time.Nanosecond), nil
	}
	return parsed, nil
}

func runValidateKnownDevices(args []string) error {
	fs := flag.NewFlagSet("validate known-devices", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "known devices CSV path, or - for stdin")
	events := fs.String("events", "", "optional normalized identity JSONL path to compare against")
	output := fs.String("output", "-", "validation report JSON path, or - for stdout")
	strict := fs.Bool("strict", false, "require 30-50 sample acceptance coverage and a passing identity comparison")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}

	in, closeInput, err := openInput(*input)
	if err != nil {
		return err
	}
	defer closeInput()
	out, closeOutput, err := openOutput(*output)
	if err != nil {
		return err
	}
	defer closeOutput()

	var report validation.KnownDeviceValidationReport
	if *events != "" {
		normalizedEvents, err := readNormalizedEventsFile(*events)
		if err != nil {
			return err
		}
		report, err = validation.AnalyzeKnownDeviceCSVWithIdentityState(in, store.BuildIdentityState(normalizedEvents))
		if err != nil {
			return err
		}
	} else {
		report, err = validation.AnalyzeKnownDeviceCSV(in)
		if err != nil {
			return err
		}
	}
	if err := writeJSON(out, report); err != nil {
		return err
	}
	comparisonFailed := 0
	if report.Comparison != nil {
		comparisonFailed = report.Comparison.Failed
	}
	fmt.Fprintf(os.Stderr, "validate known-devices: valid=%t samples=%d errors=%d warnings=%d comparison_failed=%d\n",
		report.Valid,
		report.Coverage.Total,
		len(report.Errors),
		len(report.Warnings),
		comparisonFailed,
	)
	if !report.Valid {
		return fmt.Errorf("known devices validation failed with %d structural error(s), %d comparison failure(s)", len(report.Errors), comparisonFailed)
	}
	if *strict && !report.AcceptanceReady {
		return fmt.Errorf("known devices acceptance is not ready: warnings=%d comparison_present=%t", len(report.Warnings), report.Comparison != nil)
	}
	return nil
}

func readNormalizedEventsFile(path string) ([]normalized.Event, error) {
	input, closeInput, err := openInput(path)
	if err != nil {
		return nil, err
	}
	defer closeInput()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	events := []normalized.Event{}
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var event normalized.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, fmt.Errorf("decode normalized events line %d: %w", line, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read normalized events: %w", err)
	}
	return events, nil
}

func runControlPlaneServe(args []string) error {
	fs := flag.NewFlagSet("control-plane serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", ":8080", "HTTP listen address")
	shadowDir := fs.String("shadow-dir", "/opt/proxy-sentinel/data/shadow", "shadow output directory")
	sensorID := fs.String("sensor-id", "office-30", "sensor identifier")
	frontendDir := fs.String("frontend-dir", "", "optional frontend dist directory to serve")
	readOnly := fs.Bool("read-only", true, "disable mutating review and reload endpoints")
	storageMode := fs.String("storage-mode", firstEnv("PROXY_SENTINEL_STORAGE_MODE", "file"), "storage mode: file, db, or dual")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN for production business storage")
	clickHouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP URL for production event and diagnostic storage")
	eventRetention := fs.Duration("event-retention", 7*24*time.Hour, "normalized event retention target, documented for DB deployments")
	diagnosticRetention := fs.Duration("diagnostic-retention", 30*24*time.Hour, "diagnostic retention target, documented for DB deployments")
	proxyConfigFile := fs.String("proxy-protocol-config", "", "trusted proxy evidence registration file")
	applicationsEnabled := fs.Bool("applications-enabled", false, "enable independent application observations")
	applicationsDir := fs.String("applications-dir", "", "durable application library and observations directory")
	fingerprintDir := fs.String("device-fingerprint-dir", "/opt/proxy-sentinel/data/device-fingerprints", "device fingerprint library directory")
	fingerprintAutoUpdate := fs.Bool("device-fingerprint-auto-update", false, "check device fingerprint sources weekly (disabled for offline deployments)")
	authFile := fs.String("auth-file", "", "local RBAC user file; empty preserves legacy fixed session")
	authCookieSecure := fs.Bool("auth-cookie-secure", false, "send the session cookie only over HTTPS")
	oidcIssuer := fs.String("oidc-issuer", os.Getenv("PROXY_SENTINEL_OIDC_ISSUER"), "optional OIDC issuer URL")
	oidcClientID := fs.String("oidc-client-id", os.Getenv("PROXY_SENTINEL_OIDC_CLIENT_ID"), "OIDC client ID")
	oidcSecretFile := fs.String("oidc-client-secret-file", os.Getenv("PROXY_SENTINEL_OIDC_CLIENT_SECRET_FILE"), "file containing the OIDC client secret")
	oidcRedirectURL := fs.String("oidc-redirect-url", os.Getenv("PROXY_SENTINEL_OIDC_REDIRECT_URL"), "OIDC callback URL")
	oidcRoleMapping := fs.String("oidc-role-mapping", os.Getenv("PROXY_SENTINEL_OIDC_ROLE_MAPPING"), "JSON mapping from OIDC groups to local roles")
	oidcDefaultRole := fs.String("oidc-default-role", firstEnv("PROXY_SENTINEL_OIDC_DEFAULT_ROLE", "viewer"), "role used when no OIDC group matches")
	exportDir := fs.String("export-dir", firstEnv("PROXY_SENTINEL_EXPORT_DIR", "/opt/proxy-sentinel/data/exports"), "directory for asynchronous CSV exports")
	sharedAccessConfig := fs.String("shared-access-config", os.Getenv("PROXY_SENTINEL_SHARED_ACCESS_CONFIG"), "controlled shared evidence source registration")
	identitySourcesConfig := fs.String("identity-sources-config", os.Getenv("PROXY_SENTINEL_IDENTITY_SOURCES_CONFIG"), "registered identity source scopes and reconciliation intervals")
	identityIngestKey := fs.String("identity-ingest-key", os.Getenv("PROXY_SENTINEL_IDENTITY_INGEST_KEY"), "bearer token for RADIUS/Portal identity event batches (defaults to PROXY_SENTINEL_IDENTITY_INGEST_KEY)")
	operationsFile := fs.String("operations-file", "", "persistent cases, organization and action state file")
	nativeConfig := fs.String("native-actions-config", os.Getenv("PROXY_SENTINEL_NATIVE_ACTIONS_CONFIG"), "private native controller and authoritative inventory configuration")
	actionMasterKey := fs.String("action-master-key", os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY"), "base secret used to encrypt northbound connector credentials (defaults to PROXY_SENTINEL_ACTION_MASTER_KEY)")
	postgresMigrationsDir := fs.String("postgres-migrations-dir", "migrations/postgres", "PostgreSQL migrations directory applied transactionally before startup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	roleMapping, err := controlplane.ParseOIDCRoleMapping(*oidcRoleMapping)
	if err != nil {
		return err
	}
	oidcSecret := ""
	if strings.TrimSpace(*oidcIssuer) != "" {
		if strings.TrimSpace(*oidcSecretFile) == "" {
			return fmt.Errorf("--oidc-client-secret-file is required when OIDC is enabled")
		}
		secret, err := os.ReadFile(*oidcSecretFile)
		if err != nil {
			return fmt.Errorf("read OIDC client secret file: %w", err)
		}
		oidcSecret = strings.TrimSpace(string(secret))
	}

	fmt.Fprintf(os.Stderr, "control-plane: addr=%s shadow_dir=%s sensor_id=%s storage_mode=%s read_only=%t event_retention=%s diagnostic_retention=%s\n", *addr, *shadowDir, *sensorID, *storageMode, *readOnly, eventRetention.String(), diagnosticRetention.String())
	if *nativeConfig != "" && strings.TrimSpace(*postgresDSN) == "" {
		return fmt.Errorf("native actions require PostgreSQL persistence")
	}
	nativeActions, closeNative, err := controlplane.LoadNativeActions(*nativeConfig)
	if err != nil {
		return err
	}
	defer closeNative()
	if err := controlplane.ValidateNativeTestListener(nativeActions, *addr); err != nil {
		return err
	}
	return controlplane.Serve(controlplane.Options{
		NativeActions:         nativeActions,
		ProxyProtocolConfig:   *proxyConfigFile,
		ApplicationsEnabled:   *applicationsEnabled,
		ApplicationsDir:       *applicationsDir,
		Addr:                  *addr,
		ShadowDir:             *shadowDir,
		SensorID:              *sensorID,
		FrontendDir:           *frontendDir,
		ReadOnly:              *readOnly,
		StorageMode:           *storageMode,
		PostgresDSN:           *postgresDSN,
		ClickHouseDSN:         *clickHouseDSN,
		CollectorKind:         "suricata",
		InterfaceName:         "ens1f1",
		FingerprintDir:        *fingerprintDir,
		FingerprintAutoUpdate: *fingerprintAutoUpdate,
		AuthFile:              *authFile,
		AuthCookieSecure:      *authCookieSecure,
		OIDC: controlplane.OIDCOptions{
			Issuer: *oidcIssuer, ClientID: *oidcClientID, ClientSecret: oidcSecret,
			RedirectURL: *oidcRedirectURL, RoleMapping: roleMapping, DefaultRole: *oidcDefaultRole,
		},
		ExportDir:             *exportDir,
		IdentityIngestKey:     *identityIngestKey,
		IdentitySourcesConfig: *identitySourcesConfig,
		SharedAccessConfig:    *sharedAccessConfig,
		OperationsFile:        *operationsFile,
		ActionMasterKey:       *actionMasterKey,
		PostgresMigrationsDir: *postgresMigrationsDir,
	})
}

func usageError() error {
	return fmt.Errorf("usage: proxy-sentinel version\n       proxy-sentinel migrate [--postgres-dir migrations/postgres] [--clickhouse-dir migrations/clickhouse]\n       proxy-sentinel ingest run --eve /var/log/suricata/eve.json --postgres-dsn <dsn> --clickhouse-dsn <dsn>\n       proxy-sentinel read-model run --lane realtime|coarse|recognition|application --postgres-dsn <dsn> --clickhouse-dsn <dsn>\n       proxy-sentinel adapter suricata --input eve.json --output events.jsonl\n       proxy-sentinel adapter zeek --input dhcp.log --output events.jsonl\n       proxy-sentinel adapter zeek --input software.log --output events.jsonl\n       proxy-sentinel adapter identity --source radius --input radius.jsonl --output events.jsonl\n       proxy-sentinel replay --input events.jsonl [--output summary.json]\n       proxy-sentinel evidence --input events.jsonl [--output evidence.json]\n       proxy-sentinel risk batch --input evidence.json --output risk-snapshots.json\n       proxy-sentinel risk list --input risk-snapshots.json [--min-level suspicious]\n       proxy-sentinel risk inspect --input evidence.json --ip 10.1.2.3\n       proxy-sentinel shadow run --eve /var/log/suricata/eve.json [--zeek-dhcp /opt/proxy-sentinel/data/zeek/logs/current/dhcp.log] [--zeek-software /opt/proxy-sentinel/data/zeek/logs/current/software.log] --state data/shadow/state.json --out-dir data/shadow\n       proxy-sentinel evaluate shadow --shadow-dir data/shadow [--daily-export-dir data/shadow/review-exports] --output report.json\n       proxy-sentinel evaluate routers --manifest examples/router/golden/manifest.json --output report.json\n       proxy-sentinel router sample --interface ens1f1 --duration 5m --work-dir data/router-samples\n       proxy-sentinel backfill identity --postgres-dsn <dsn> --clickhouse-dsn <dsn> [--window 7d]\n       proxy-sentinel control-plane serve --addr :8080 --shadow-dir data/shadow --frontend-dir frontend/dist --read-only\n       proxy-sentinel validate known-devices --input examples/known-devices-template.csv [--events normalized-identity.jsonl] [--strict] --output -")
}

func firstEnv(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func openInput(path string) (*os.File, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	return file, file.Close, nil
}

func openOutput(path string) (*os.File, func() error, error) {
	if path == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output: %w", err)
	}
	return file, file.Close, nil
}

func openOutputWithParents(path string) (*os.File, func() error, error) {
	if path != "-" {
		parent := filepath.Dir(path)
		if parent != "." {
			if err := os.MkdirAll(parent, 0o750); err != nil {
				return nil, nil, fmt.Errorf("create output directory: %w", err)
			}
		}
	}
	return openOutput(path)
}

func writeJSON(output *os.File, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
