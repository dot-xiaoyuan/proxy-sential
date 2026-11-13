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
	"path/filepath"
	"syscall"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

const zeekDHCPStreamParser = "zeek-v1"
const zeekDHCPBindingStreamParser = "zeek-dhcp-binding-v2"
const zeekDHCPMessageStreamParser = "zeek-dhcp-message-v1"
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

func streamParserForSourcePath(kind, path string) string {
	if kind == "zeek-dhcp-binding" && filepath.Base(path) == "device_dhcp_message.log" {
		return zeekDHCPMessageStreamParser
	}
	return streamParserForSource(kind)
}

func controlledScopeBindingHash(fileHash, interfaceName string) string {
	if len(fileHash) != 64 || interfaceName == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fileHash + "\x00" + interfaceName))
	return hex.EncodeToString(sum[:])
}

func verifyIngestStreamCutover(ctx context.Context, db *sql.DB, cursor streamlog.SourceCursor, sensor, scopeHash string) error {
	if db == nil || cursor.Path == "" || cursor.Epoch == "" || cursor.ParserVersion != streamParserForSourcePath(cursor.Source, cursor.Path) || cursor.ParserVersion == "" || cursor.Offset < 0 || cursor.DiscardedBeforeOffset < 0 {
		return errors.New("invalid controlled file stream cursor")
	}
	if cursor.Source == "zeek-dhcp-binding" && (cursor.KeyScheme != "generation-v2" || cursor.Generation == 0) {
		return errors.New("verified DHCP binding requires a file generation key")
	}
	var registeredSensor, registeredFile, parser, manifest, registeredScope string
	var start int64
	var cutoverAt time.Time
	err := db.QueryRowContext(ctx, `SELECT sensor_id,file_id,start_offset,parser_version,cancel_manifest_sha256,capture_scope_sha256,cutover_at
 FROM stream_source_cutovers WHERE epoch=$1 AND source_kind=$2 AND source_path=$3 AND state='active'`, cursor.Epoch, cursor.Source, cursor.Path).
		Scan(&registeredSensor, &registeredFile, &start, &parser, &manifest, &registeredScope, &cutoverAt)
	if err != nil {
		return fmt.Errorf("active file source cutover missing: %w", err)
	}
	if registeredSensor != sensor || parser != cursor.ParserVersion || start != cursor.DiscardedBeforeOffset || manifest == "" || scopeHash == "" || registeredScope != scopeHash ||
		(cursor.LastSegmentID == "" && registeredFile != cursor.FileID) {
		return errors.New("file stream cursor does not match audited cutover")
	}
	// The cutover offset belongs to the original file. After rotation, Offset
	// starts at zero in the next file while DiscardedBeforeOffset remains the
	// immutable original cutoff. Require a committed segment and a newer file
	// generation before accepting an offset below that cutoff. A recycled inode
	// can reuse the original file ID; prove that file is newer and its committed
	// tail is intact before accepting that collision.
	if cursor.Offset < cursor.DiscardedBeforeOffset {
		if cursor.LastSegmentID == "" ||
			(cursor.KeyScheme == "generation-v2" && cursor.Generation <= 1) ||
			(cursor.KeyScheme != "generation-v2" && registeredFile == cursor.FileID && !proveReusedFileCursor(cursor, cutoverAt)) {
			return errors.New("file stream cursor rewound below audited cutover")
		}
	}
	return nil
}

func proveReusedFileCursor(cursor streamlog.SourceCursor, cutoverAt time.Time) bool {
	if cursor.TailBytes <= 0 || cursor.TailBytes > streamlog.SourceTailProofBytes || cursor.Offset < int64(cursor.TailBytes) || len(cursor.TailSHA256) != 64 {
		return false
	}
	f, err := os.Open(cursor.Path)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || realtime.FileIdentity(cursor.Path, info) != cursor.FileID || info.Size() < cursor.Offset {
		return false
	}
	birth, ok := fileBirthTime(f)
	if !ok || !birth.After(cutoverAt) {
		return false
	}
	tail := make([]byte, cursor.TailBytes)
	if _, err := f.ReadAt(tail, cursor.Offset-int64(cursor.TailBytes)); err != nil {
		return false
	}
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]) == cursor.TailSHA256
}

// sameSourceFilePath reports whether two configured paths resolve to the same
// file, so a symlinked or retained alias does not masquerade as a second DHCP
// source that still needs retirement.
func sameSourceFilePath(a, b string) bool {
	if a == b {
		return true
	}
	resolvedA, errA := filepath.EvalSymlinks(a)
	resolvedB, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && resolvedA == resolvedB
}

func runIngestStream(args []string) error {
	fs := flag.NewFlagSet("ingest stream-run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sensor := fs.String("sensor-id", os.Getenv("PROXY_SENTINEL_SENSOR_ID"), "registered capture sensor")
	path := fs.String("zeek-dhcp", "", "already enabled Zeek DHCP log")
	bindingPath := fs.String("zeek-dhcp-binding", "", "same-scope Zeek DHCP binding log")
	messagePath := fs.String("zeek-dhcp-message", "", "per-message Zeek DHCP log; replaces the binding-file source after audited retirement")
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
	drainOnly := fs.Bool("drain-only", false, "finish only previously accepted journal segments")
	deviceManifestWrites := fs.Bool("device-signal-manifest-writes", false, "use segment receipt manifests for device-signals after compatible reader release")
	deviceStream4Keys := fs.Bool("device-signal-stream4-keys", false, "emit segment-located device signal keys only after the PG248 compatible reader is the rollback release")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sensor == "" || (*path == "" && *bindingPath == "" && *messagePath == "" && *ttlPath == "" && *handshakePath == "" && *routerProbePath == "") || *journalDir == "" || *scopeFile == "" || *postgresDSN == "" || *clickhouseDSN == "" {
		return errors.New("stream-run requires sensor, an audited file source, journal, scope and both database DSNs")
	}
	if *messagePath != "" && (*bindingPath != "" || *path != "" || filepath.Base(*messagePath) != "device_dhcp_message.log") {
		return errors.New("DHCP message source must replace other DHCP file sources and use device_dhcp_message.log")
	}
	if *path != "" && *bindingPath != "" {
		return errors.New("aggregate and verified DHCP bindings cannot be consumed together")
	}
	if *maxBytes <= 0 || *maxBytes > 1<<20 || *poll <= 0 || *storeTimeout <= 0 || *storeTimeout > 3*time.Second || *pending < 1 || *pending > 64 {
		return errors.New("stream-run bounds are invalid")
	}
	library, err := fingerprint.OpenInstalledRuntime()
	if err != nil {
		return err
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
	db.SetMaxOpenConns(store.PostgresPoolLimit(2))
	db.SetMaxIdleConns(store.PostgresPoolLimit(2))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *deviceManifestWrites {
		if *ttlPath == "" && *handshakePath == "" && *routerProbePath == "" {
			return errors.New("device signal manifest writer requires a device-signals source")
		}
		if err := verifyDeviceSignalManifestSchema(ctx, db); err != nil {
			return err
		}
	}
	if *deviceStream4Keys {
		if *ttlPath == "" && *handshakePath == "" && *routerProbePath == "" {
			return errors.New("device signal stream4 key writer requires a device-signals source")
		}
		if err := verifyDeviceSignalStream4Schema(ctx, db); err != nil {
			return err
		}
	}
	if library != nil {
		go library.WatchInstalled(ctx)
	}
	// The legacy reader uses this same advisory lease. It must be stopped before
	// the source is activated, so the file never feeds both physical body tables.
	leaseStore, err := store.NewPostgresStore(store.PostgresOptions{DSN: *postgresDSN, SensorID: *sensor})
	if err != nil {
		return err
	}
	defer leaseStore.Close()
	if *messagePath != "" {
		rows, err := db.QueryContext(ctx, `SELECT source_kind, source_path FROM stream_source_cutovers
WHERE state='active' AND sensor_id=$1 AND (source_kind='zeek-dhcp' OR source_kind='zeek-dhcp-binding')`, *sensor)
		if err != nil {
			return fmt.Errorf("check retired DHCP file sources: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var kind, sourcePath string
			if err = rows.Scan(&kind, &sourcePath); err != nil {
				return fmt.Errorf("check retired DHCP file sources: %w", err)
			}
			// A fresh per-message stream may coexist with stale cutovers that
			// point at the same file through a different path (for example a
			// retained directory or symlink); only a genuinely different DHCP
			// file still needs its legacy reader retired.
			if kind == "zeek-dhcp" || !sameSourceFilePath(sourcePath, *messagePath) {
				return errors.New("retire old DHCP aggregate and binding sources before starting the per-message source")
			}
		}
		if err = rows.Err(); err != nil {
			return fmt.Errorf("check retired DHCP file sources: %w", err)
		}
	}
	sources := make([]realtime.Source, 0, 5)
	releases := make([]func(), 0, 5)
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for _, item := range []struct{ kind, path string }{{"zeek-dhcp", *path}, {"zeek-dhcp-binding", *bindingPath}, {"zeek-dhcp-binding", *messagePath}, {"device-signals", *ttlPath}, {"device-signals", *handshakePath}, {"device-signals", *routerProbePath}} {
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
	projector := discovery.StreamDiscoveryProjector{DB: db, DeviceSignalManifestWrites: *deviceManifestWrites}
	writer := store.StreamLaneWriter{ClickHouse: ch, Projector: projector, RiskQueue: projector, SharedQueue: store.StreamSharedJobQueue{DB: db}}
	archiveWorkers, searchWorkers := 1, 1
	if *ttlPath != "" || *handshakePath != "" {
		archiveWorkers, searchWorkers = 2, 2
	}
	return realtime.RunStream(ctx, journal, writer, realtime.StreamRunOptions{
		Capture:            realtime.Options{SensorID: *sensor, Sources: sources, PollInterval: *poll, MaxBatchBytes: *maxBytes, StoreTimeout: *storeTimeout, DeviceSignalStream4Keys: *deviceStream4Keys},
		MaxPendingSegments: *pending,
		ArchiveWorkers:     archiveWorkers,
		SearchWorkers:      searchWorkers,
		DrainOnly:          *drainOnly,
	})
}

func verifyDeviceSignalManifestSchema(ctx context.Context, db *sql.DB) error {
	var ready bool
	err := db.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('stream_discovery_event_keys')
  AND attname='receipt_segment_id' AND NOT attisdropped)
 AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass('stream_discovery_event_keys')
  AND attname='receipt_ordinal' AND NOT attisdropped)
 AND to_regprocedure('sentinel_device_signal_manifest_evidence(jsonb)') IS NOT NULL
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('stream_discovery_segment_receipt_manifests')
  AND conname='stream_discovery_manifest_key_scheme' AND pg_get_constraintdef(oid) LIKE '%device-signals%')
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('stream_discovery_event_keys')
  AND tgname='protect_device_manifest_key' AND tgenabled IN ('O','A'))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('stream_projection_segments')
  AND tgname='protect_device_manifest_segment' AND tgenabled IN ('O','A'))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('stream_discovery_segment_receipt_manifests')
  AND tgname='protect_device_manifest_manifest' AND tgenabled IN ('O','A'))`).Scan(&ready)
	if err != nil {
		return fmt.Errorf("device signal manifest schema preflight: %w", err)
	}
	if !ready {
		return errors.New("device signal manifest schema PG247 is not installed")
	}
	return nil
}

func verifyDeviceSignalStream4Schema(ctx context.Context, db *sql.DB) error {
	var ready bool
	err := db.QueryRowContext(ctx, `SELECT
 to_regprocedure('sentinel_device_stream4_locator(text,text)') IS NOT NULL
 AND to_regprocedure('sentinel_device_stream4_evidence(jsonb)') IS NOT NULL
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('stream_projection_segments')
  AND conname='stream_projection_passive_key_scheme' AND pg_get_constraintdef(oid) LIKE '%stream4%')
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('stream_projection_segments')
  AND conname='stream_projection_device_stream4_shape')
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('stream_discovery_segment_receipt_manifests')
  AND conname='stream_discovery_manifest_key_scheme' AND pg_get_constraintdef(oid) LIKE '%stream4%')
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('stream_projection_segments')
  AND tgname='protect_stream4_segment_metadata' AND tgenabled IN ('O','A'))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('stream_discovery_segment_receipt_manifests')
  AND tgname='protect_stream4_manifest_metadata' AND tgenabled IN ('O','A'))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('stream_projection_segments')
  AND tgname='protect_stream4_segment_truncate' AND tgenabled IN ('O','A'))
 AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('stream_discovery_segment_receipt_manifests')
  AND tgname='protect_stream4_manifest_truncate' AND tgenabled IN ('O','A'))`).Scan(&ready)
	if err != nil {
		return fmt.Errorf("device signal stream4 schema preflight: %w", err)
	}
	if !ready {
		return errors.New("device signal stream4 schema PG248 is not installed")
	}
	return nil
}
