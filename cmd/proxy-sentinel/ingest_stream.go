package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

const zeekDHCPStreamParser = "zeek-v1"
const zeekDHCPBindingStreamParser = "zeek-dhcp-binding-v2"
const deviceSignalStreamParser = "device-v1"

func streamParserForSource(kind string) string {
	switch kind {
	case "zeek-dhcp":
		return zeekDHCPStreamParser
	case "zeek-dhcp-binding":
		return zeekDHCPBindingStreamParser
	case "device-signals":
		return deviceSignalStreamParser
	default:
		return ""
	}
}

func controlledScopeBindingHash(fileHash, interfaceName string) string {
	if len(fileHash) != 64 || interfaceName == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fileHash + "\x00" + interfaceName))
	return hex.EncodeToString(sum[:])
}

func verifyIngestStreamCutover(ctx context.Context, db *sql.DB, cursor streamlog.SourceCursor, sensor, scopeHash string) error {
	if db == nil || cursor.Path == "" || cursor.Epoch == "" || cursor.ParserVersion != streamParserForSource(cursor.Source) || cursor.ParserVersion == "" || cursor.Offset < cursor.DiscardedBeforeOffset {
		return errors.New("invalid controlled file stream cursor")
	}
	if cursor.Source == "zeek-dhcp-binding" && (cursor.KeyScheme != "generation-v2" || cursor.Generation == 0) {
		return errors.New("verified DHCP binding requires a file generation key")
	}
	var registeredSensor, registeredFile, parser, manifest, registeredScope string
	var start int64
	err := db.QueryRowContext(ctx, `SELECT sensor_id,file_id,start_offset,parser_version,cancel_manifest_sha256,capture_scope_sha256
 FROM stream_source_cutovers WHERE epoch=$1 AND source_kind=$2 AND source_path=$3 AND state='active'`, cursor.Epoch, cursor.Source, cursor.Path).
		Scan(&registeredSensor, &registeredFile, &start, &parser, &manifest, &registeredScope)
	if err != nil {
		return fmt.Errorf("active file source cutover missing: %w", err)
	}
	if registeredSensor != sensor || parser != cursor.ParserVersion || start != cursor.DiscardedBeforeOffset || manifest == "" || scopeHash == "" || registeredScope != scopeHash ||
		(cursor.LastSegmentID == "" && registeredFile != cursor.FileID) {
		return errors.New("file stream cursor does not match audited cutover")
	}
	return nil
}

func runIngestStream(args []string) error {
	fs := flag.NewFlagSet("ingest stream-run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered capture sensor")
	path := fs.String("zeek-dhcp", "", "already enabled Zeek DHCP log")
	bindingPath := fs.String("zeek-dhcp-binding", "", "same-scope Zeek DHCP binding log")
	ttlPath := fs.String("device-signals", "", "controlled TTL device signal log")
	handshakePath := fs.String("handshake-signals", "", "controlled handshake device signal log")
	routerProbePath := fs.String("router-probe-signals", "", "controlled router probe signal log")
	controlledInterface := fs.String("controlled-interface", "", "operator-verified source interface")
	journalDir := fs.String("journal-dir", "", "durable source journal")
	scopeFile := fs.String("capture-scope-config", os.Getenv("PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG"), "controlled capture scope")
	postgresDSN := fs.String("postgres-dsn", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"), "PostgreSQL DSN")
	clickhouseDSN := fs.String("clickhouse-dsn", os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), "ClickHouse HTTP DSN")
	poll := fs.Duration("poll-interval", 500*time.Millisecond, "source polling interval")
	maxBytes := fs.Int64("max-batch-bytes", 1<<20, "source bytes per durable segment")
	storeTimeout := fs.Duration("store-timeout", 3*time.Second, "individual storage attempt budget")
	pending := fs.Int("max-pending-segments", 16, "bounded queued segments")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sensor == "" || (*path == "" && *bindingPath == "" && *ttlPath == "" && *handshakePath == "" && *routerProbePath == "") || *journalDir == "" || *scopeFile == "" || *postgresDSN == "" || *clickhouseDSN == "" {
		return errors.New("stream-run requires sensor, an audited file source, journal, scope and both database DSNs")
	}
	if *path != "" && *bindingPath != "" {
		return errors.New("aggregate and verified DHCP bindings cannot be consumed together")
	}
	if *maxBytes <= 0 || *maxBytes > 1<<20 || *poll <= 0 || *storeTimeout <= 0 || *storeTimeout > 3*time.Second || *pending < 1 || *pending > 64 {
		return errors.New("stream-run bounds are invalid")
	}
	scope, scopeHash, err := loadCaptureScopeWithHash(*scopeFile)
	if err != nil {
		return err
	}
	if scope == nil || scope.SensorID != *sensor || scope.CollectorInstanceID == "" ||
		time.Now().Before(scope.ValidFrom) || !time.Now().Before(scope.ValidUntil) {
		return errors.New("stream-run requires a currently valid matching capture scope")
	}
	if *controlledInterface == "" {
		*controlledInterface = scope.InterfaceName
	}
	if *controlledInterface == "" || (scope.InterfaceName != "" && *controlledInterface != scope.InterfaceName) {
		return errors.New("stream-run requires an operator-verified matching interface")
	}
	scopeHash = controlledScopeBindingHash(scopeHash, *controlledInterface)
	journal, err := streamlog.Open(*journalDir)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", *postgresDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The legacy reader uses this same advisory lease. It must be stopped before
	// the source is activated, so the file never feeds both physical body tables.
	leaseStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: *postgresDSN, SensorID: *sensor})
	if err != nil {
		return err
	}
	defer leaseStore.Close()
	sources := make([]realtime.Source, 0, 5)
	releases := make([]func(), 0, 5)
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for _, item := range []struct{ kind, path string }{{"zeek-dhcp", *path}, {"zeek-dhcp-binding", *bindingPath}, {"device-signals", *ttlPath}, {"device-signals", *handshakePath}, {"device-signals", *routerProbePath}} {
		if item.path == "" {
			continue
		}
		cursor, err := journal.LoadSource(item.kind, item.path)
		if err != nil {
			return fmt.Errorf("fresh source %s at %s was not initialized: %w", item.kind, item.path, err)
		}
		if err := verifyIngestStreamCutover(ctx, db, cursor, *sensor, scopeHash); err != nil {
			return err
		}
		release, err := leaseStore.AcquireIngestSourceLease(ctx, item.kind, item.path)
		if err != nil {
			return err
		}
		releases = append(releases, release)
		sources = append(sources, realtime.Source{Kind: item.kind, Path: item.path, CaptureScope: scope, ControlledInterface: *controlledInterface, CollectorInstanceID: scope.CollectorInstanceID})
	}
	ch, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: *clickhouseDSN, RequestTimeout: *storeTimeout})
	if err != nil {
		return err
	}
	projector := discovery.StreamDiscoveryProjector{DB: db}
	writer := store.StreamLaneWriter{ClickHouse: ch, Projector: projector, RiskQueue: projector, SharedQueue: store.StreamSharedJobQueue{DB: db}}
	return realtime.RunStream(ctx, journal, writer, realtime.StreamRunOptions{
		Capture:            realtime.Options{SensorID: *sensor, Sources: sources, PollInterval: *poll, MaxBatchBytes: *maxBytes, StoreTimeout: *storeTimeout},
		MaxPendingSegments: *pending,
	})
}
