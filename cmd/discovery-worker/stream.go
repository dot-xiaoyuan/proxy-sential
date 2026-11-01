package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/eventbus"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

type passiveStreamOptions struct {
	Interface  string
	Spool      string
	JournalDir string
	ScopeFile  string
	Node       string
	Site       string
	Domain     string
	AllowCIDRs string
	Collection discovery.CollectionConfig
	DrainOnly  bool
}

func passiveStreamProcessor(journal streamlog.ProcessorJournal, writer streamlog.Writer) streamlog.Processor {
	// Start each RPC budget after local decode and durable attempt fsync. A
	// shared-disk stall must not strand an unsent request as an ambiguous write.
	return streamlog.Processor{Journal: journal, Writer: writer, SinkTimeout: 30 * time.Second, ProjectionRetryTimeout: 120 * time.Second, FinalizeTimeout: 30 * time.Second}
}

func verifyPassiveStreamCutover(ctx context.Context, db *sql.DB, cursor streamlog.SourceCursor, sensor string) error {
	if cursor.Source != "passive-discovery" || cursor.Epoch == "" || cursor.Path == "" || cursor.ParserVersion != discovery.PassiveStreamParserVersion || cursor.Offset < 0 {
		return errors.New("invalid passive stream cursor")
	}
	var registeredSensor, fileID, parser, manifest string
	var start int64
	err := db.QueryRowContext(ctx, `SELECT sensor_id,file_id,start_offset,parser_version,cancel_manifest_sha256
 FROM stream_source_cutovers WHERE epoch=$1 AND source_kind=$2 AND source_path=$3 AND state='active'`, cursor.Epoch, cursor.Source, cursor.Path).Scan(&registeredSensor, &fileID, &start, &parser, &manifest)
	if err != nil {
		return fmt.Errorf("active fresh source cutover missing: %w", err)
	}
	if registeredSensor != sensor || parser != cursor.ParserVersion || start != cursor.DiscardedBeforeOffset || manifest == "" ||
		(cursor.LastSegmentID == "" && fileID != cursor.FileID) {
		return errors.New("passive stream cursor does not match audited cutover")
	}
	return nil
}

func runPassiveStreamWorker(opts passiveStreamOptions) (result error) {
	if opts.Interface == "" || opts.Node == "" || opts.Site == "" || opts.Domain == "" || opts.JournalDir == "" || opts.ScopeFile == "" {
		return errors.New("stream discovery requires interface, node, site, domain, journal and controlled scope")
	}
	scope, err := normalized.LoadCaptureScope(opts.ScopeFile)
	if err != nil {
		return err
	}
	if scope == nil {
		return errors.New("stream discovery capture scope is required")
	}
	if scope.SensorID != opts.Node || scope.CampusID != opts.Site || scope.AccessDomain != opts.Domain || scope.InterfaceName != opts.Interface {
		return errors.New("stream discovery scope and source disagree")
	}
	if time.Now().Before(scope.ValidFrom) || !time.Now().Before(scope.ValidUntil) {
		return errors.New("stream discovery capture scope is outside its validity interval")
	}
	allow, err := discovery.ParseCaptureCIDRs(opts.AllowCIDRs)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(store.PostgresPoolLimit(2))
	db.SetMaxIdleConns(store.PostgresPoolLimit(2))
	runtimeDB, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil {
		return err
	}
	defer runtimeDB.Close()
	runtimeDB.SetMaxOpenConns(2)
	runtimeDB.SetMaxIdleConns(2)
	ch, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN")})
	if err != nil {
		return err
	}
	legacyJournal, err := streamlog.Open(opts.JournalDir)
	if err != nil {
		return err
	}
	source := discovery.Source{ID: "passive-" + opts.Node, Node: opts.Node, Site: opts.Site, Domain: opts.Domain, Address: opts.Interface, ConfigVersion: 1}
	path := discovery.PassiveStreamSourcePath(source)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Compatibility comes before activation. This binary can drain WAL-backed
	// segments, but live WAL writes remain unavailable until rotation/checkpoint
	// and rollback have been validated. Existing v1 capture keeps its protocol.
	journal, err := streamlog.OpenPassiveWALJournal(legacyJournal, path, streamlog.PassiveWALOptions{
		QuarantineDir: filepath.Join(opts.Spool, "discovery-quarantine"),
		BeforeRecovery: func(cursor streamlog.SourceCursor) error {
			return verifyPassiveStreamCutover(ctx, db, cursor, opts.Node)
		},
	})
	if err != nil {
		return err
	}
	defer func() { stop(); result = errors.Join(result, journal.Close()) }()
	cursor, err := journal.LoadSource("passive-discovery", path)
	if err != nil {
		return fmt.Errorf("fresh stream source was not initialized: %w", err)
	}
	if err := verifyPassiveStreamCutover(ctx, db, cursor, opts.Node); err != nil {
		return err
	}
	recovered, err := journal.RecoverSource("passive-discovery", path)
	if err != nil {
		return err
	}
	for _, id := range recovered {
		quarantinePath := filepath.Join(opts.Spool, "discovery-quarantine", id+".json")
		if _, err := os.Stat(quarantinePath); err == nil {
			log.Printf("passive stream paused for quarantined, unprocessed segment=%s manifest=%s", id, quarantinePath)
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// This compatibility release always dual-writes any stream2 segment it
	// encounters, including after rollback from a later compact-only release.
	projector := discovery.StreamDiscoveryProjector{DB: db}
	writer := store.StreamLaneWriter{ClickHouse: ch, Projector: projector, RiskQueue: projector}
	if opts.DrainOnly {
		processor := streamlog.Processor{Journal: journal, Writer: writer}
		for _, id := range recovered {
			for attempt := 0; attempt < 3; attempt++ {
				// This is stopped-source recovery, outside the live 5-second
				// acceptance window. Old state files can spend seconds in
				// fsync on the shared HDD; do not cut off a DB request with
				// the realtime worker's total three-second budget.
				attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				err := processor.Drain(attemptCtx, id)
				cancel()
				if err == nil {
					break
				}
				if errors.Is(err, streamlog.ErrContentConflict) || errors.Is(err, streamlog.ErrQuarantined) || errors.Is(err, streamlog.ErrPassiveWALStopped) || errors.Is(err, discovery.ErrUnsupportedStreamProjection) {
					return err
				}
				if errors.Is(err, discovery.ErrStreamFactScopeMismatch) {
					manifest, quarantineErr := quarantinePassiveSegment(journal, opts.JournalDir, opts.Spool, id, err)
					if quarantineErr != nil {
						return fmt.Errorf("quarantine passive segment %s: %w", id, quarantineErr)
					}
					return fmt.Errorf("passive segment %s quarantined at %s: %w", id, manifest, err)
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if attempt == 2 {
					return fmt.Errorf("passive stream recovery segment %s remains unconfirmed after three bounded checks: %w", id, err)
				}
				log.Printf("passive stream recovery segment %s remains unconfirmed: %v", id, err)
				time.Sleep(time.Second)
			}
		}
		return nil
	}
	runtimeRepo := discovery.Repository{DB: runtimeDB}
	if _, err := runtimeDB.ExecContext(ctx, `UPDATE discovery_protocol_runtime SET received=0,parsed=0,rejected=0,admitted=0,last_seen=NULL,last_success=NULL,error='' WHERE sensor_id=$1 AND owner='discovery-worker'`, opts.Node); err != nil {
		return fmt.Errorf("reset stream protocol runtime: %w", err)
	}
	if err := runtimeRepo.ConfigureProtocolRuntime(ctx, opts.Node, opts.Collection); err != nil {
		return fmt.Errorf("configure stream protocol runtime: %w", err)
	}
	statsDir := filepath.Join(opts.Spool, "stream-capture-stats")
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := runtimeRepo.UpdateCaptureRuntime(ctx, statsDir, opts.Node); err != nil && ctx.Err() == nil {
					log.Printf("stream capture runtime: %v", err)
				}
				if _, err := runtimeDB.ExecContext(ctx, `UPDATE discovery_protocol_runtime SET admitted=parsed,last_success=CASE WHEN parsed>0 THEN now() ELSE last_success END WHERE sensor_id=$1 AND owner='discovery-worker'`, opts.Node); err != nil && ctx.Err() == nil {
					log.Printf("stream admitted runtime: %v", err)
				}
			}
		}
	}()
	shadow, shadowErr := eventbus.NewShadowFromEnv(ctx, opts.Node, statsDir, discovery.StreamPartitionKey)
	if shadowErr != nil {
		log.Printf("event-bus shadow disabled: %v", shadowErr)
		eventbus.WriteDisabledStats(statsDir, shadowErr)
	}
	if shadow != nil {
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := shadow.Close(closeCtx); err != nil {
				log.Printf("event-bus shadow close: %v", err)
			}
		}()
	}
	metrics := newPassiveStreamMetrics()
	processor := passiveStreamProcessor(journal, writer)
	processor.Observer = metrics.observe
	archiveQueue := make(chan string, 64)
	searchQueue := make(chan string, 64)
	projectionQueue := make(chan string, 64)
	finalizeQueue := make(chan passiveFinalizerSignal, 256)
	metricsDone := make(chan struct{})
	sampleQueues := func() {
		metrics.queue("archive", len(archiveQueue), cap(archiveQueue))
		metrics.queue("search", len(searchQueue), cap(searchQueue))
		metrics.queue("projection", len(projectionQueue), cap(projectionQueue))
		metrics.queue("finalizer", len(finalizeQueue), cap(finalizeQueue))
	}
	go func() {
		defer close(metricsDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sampleQueues()
				metrics.report("periodic")
			}
		}
	}()
	defer func() {
		stop()
		<-metricsDone
		sampleQueues()
		metrics.report("shutdown")
	}()

	laneResults := make(chan error, 4)
	maintenanceResult := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				maintenanceResult <- nil
				return
			case <-ticker.C:
				if _, err := projector.ExpireStreamDiscoveryStates(ctx, 100); err != nil {
					if ctx.Err() == nil {
						maintenanceResult <- fmt.Errorf("stream discovery expiry: %w", err)
						stop()
						return
					}
					maintenanceResult <- nil
					return
				}
			}
		}
	}()
	runLane := func(lane streamlog.Lane, queue <-chan string) {
		var lastReport time.Time
		for {
			select {
			case <-ctx.Done():
				laneResults <- nil
				return
			case id := <-queue:
				metrics.queue(string(lane), len(queue), cap(queue))
				for {
					err := processor.DrainLane(ctx, id, lane)
					if err == nil {
						break
					}
					if ctx.Err() != nil {
						laneResults <- nil
						return
					}
					if errors.Is(err, streamlog.ErrContentConflict) || errors.Is(err, streamlog.ErrQuarantined) || errors.Is(err, streamlog.ErrPassiveWALStopped) || errors.Is(err, discovery.ErrUnsupportedStreamProjection) {
						laneResults <- err
						stop()
						return
					}
					if errors.Is(err, discovery.ErrStreamFactScopeMismatch) {
						manifest, quarantineErr := quarantinePassiveSegment(journal, opts.JournalDir, opts.Spool, id, err)
						if quarantineErr != nil {
							laneResults <- fmt.Errorf("quarantine passive segment %s: %w", id, quarantineErr)
						} else {
							laneResults <- fmt.Errorf("passive segment %s quarantined at %s: %w", id, manifest, err)
						}
						stop()
						return
					}
					if time.Since(lastReport) >= 30*time.Second {
						log.Printf("passive stream %s lane segment %s remains unconfirmed: %v", lane, id, err)
						lastReport = time.Now()
					}
					select {
					case <-ctx.Done():
						laneResults <- nil
						return
					case <-time.After(200 * time.Millisecond):
					}
				}
				started := time.Now()
				select {
				case finalizeQueue <- passiveFinalizerSignal{id: id, lane: lane}:
					metrics.observe("", "enqueue", time.Since(started), nil)
					metrics.queue("finalizer", len(finalizeQueue), cap(finalizeQueue))
				case <-ctx.Done():
					metrics.observe("", "enqueue", time.Since(started), ctx.Err())
					laneResults <- nil
					return
				}
			}
		}
	}
	go runLane(streamlog.Archive, archiveQueue)
	go runLane(streamlog.Search, searchQueue)
	go runLane(streamlog.Projection, projectionQueue)
	go func() {
		err := runPassiveFinalizer(ctx, finalizeQueue, processor.FinalizeAfterLanes, time.Second, 256)
		if err != nil {
			stop()
		}
		laneResults <- err
	}()
	enqueue := func(id string) error {
		for i, queue := range []chan string{archiveQueue, searchQueue, projectionQueue} {
			lane := []streamlog.Lane{streamlog.Archive, streamlog.Search, streamlog.Projection}[i]
			if err := enqueuePassiveLane(ctx, queue, id, lane, metrics); err != nil {
				return err
			}
		}
		return nil
	}
	for _, id := range recovered {
		if err := enqueue(id); err != nil {
			stop()
			// Join lanes before the deferred final metrics snapshot, including failures
			// while recovering the durable backlog before capture starts.
			for range 4 {
				<-laneResults
			}
			<-maintenanceResult
			return err
		}
	}
	captureErr := discovery.CaptureStreamConfigured(ctx, opts.Interface, statsDir, source, allow, opts.Collection, journal, scope, func(captured discovery.CapturedSegment) error {
		metrics.observe("capture", "append_commit", captured.AppendCommitDuration, nil)
		if shadow != nil {
			shadow.Publish(captured.ID, captured.Segment)
		}
		return enqueue(captured.ID)
	})
	stop()
	var consumerErr error
	for range 4 {
		if err := <-laneResults; err != nil && consumerErr == nil {
			consumerErr = err
		}
	}
	maintenanceErr := <-maintenanceResult
	if consumerErr != nil {
		return consumerErr
	}
	if maintenanceErr != nil {
		return maintenanceErr
	}
	// Capture normalizes a clean cancellation to this sentinel. A joined error
	// can also contain a real persistence failure and must not be hidden.
	if captureErr != nil && captureErr != context.Canceled {
		return captureErr
	}
	return nil
}
