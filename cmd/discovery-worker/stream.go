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

func runPassiveStreamWorker(opts passiveStreamOptions) error {
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
	ch, err := store.NewClickHouseStore(store.ClickHouseOptions{DSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN")})
	if err != nil {
		return err
	}
	journal, err := streamlog.Open(opts.JournalDir)
	if err != nil {
		return err
	}
	source := discovery.Source{ID: "passive-" + opts.Node, Node: opts.Node, Site: opts.Site, Domain: opts.Domain, Address: opts.Interface, ConfigVersion: 1}
	path := discovery.PassiveStreamSourcePath(source)
	release, err := journal.AcquireSourceLease("passive-discovery", path)
	if err != nil {
		return err
	}
	defer release()
	cursor, err := journal.LoadSource("passive-discovery", path)
	if err != nil {
		return fmt.Errorf("fresh stream source was not initialized: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := verifyPassiveStreamCutover(ctx, db, cursor, opts.Node); err != nil {
		return err
	}
	recovered, err := journal.RecoverSource("passive-discovery", path)
	if err != nil {
		return err
	}
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
				if errors.Is(err, streamlog.ErrContentConflict) || errors.Is(err, streamlog.ErrQuarantined) || errors.Is(err, discovery.ErrUnsupportedStreamProjection) {
					return err
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
	processor := streamlog.Processor{Journal: journal, Writer: writer}
	archiveQueue := make(chan string, 64)
	searchQueue := make(chan string, 64)
	projectionQueue := make(chan string, 64)
	finalizeQueue := make(chan string, 256)
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
				for {
					attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
					err := processor.DrainLane(attemptCtx, id, lane)
					cancel()
					if err == nil {
						break
					}
					if ctx.Err() != nil {
						laneResults <- nil
						return
					}
					if errors.Is(err, streamlog.ErrContentConflict) || errors.Is(err, streamlog.ErrQuarantined) || errors.Is(err, discovery.ErrUnsupportedStreamProjection) {
						laneResults <- err
						stop()
						return
					}
					if !errors.Is(err, streamlog.ErrUnconfirmed) && time.Since(lastReport) >= 30*time.Second {
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
				select {
				case finalizeQueue <- id:
				case <-ctx.Done():
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
		finalized := map[string]bool{}
		signals := map[string]uint8{}
		var lastReport time.Time
		for {
			select {
			case <-ctx.Done():
				laneResults <- nil
				return
			case id := <-finalizeQueue:
				signals[id]++
				if finalized[id] {
					if signals[id] == 3 {
						delete(finalized, id)
						delete(signals, id)
					}
					continue
				}
				for {
					attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
					err := processor.FinalizeAfterLanes(attemptCtx, id)
					cancel()
					if err == nil {
						finalized[id] = true
						if signals[id] == 3 {
							delete(finalized, id)
							delete(signals, id)
						}
						break
					}
					if errors.Is(err, streamlog.ErrUnconfirmed) {
						break // A later lane acknowledgement will enqueue this ID again.
					}
					if ctx.Err() != nil {
						laneResults <- nil
						return
					}
					if errors.Is(err, streamlog.ErrContentConflict) || errors.Is(err, streamlog.ErrQuarantined) {
						laneResults <- err
						stop()
						return
					}
					if time.Since(lastReport) >= 30*time.Second {
						log.Printf("passive stream segment %s finalization remains unconfirmed: %v", id, err)
						lastReport = time.Now()
					}
					select {
					case <-ctx.Done():
						laneResults <- nil
						return
					case <-time.After(200 * time.Millisecond):
					}
				}
			}
		}
	}()
	enqueue := func(id string) error {
		for _, queue := range []chan string{archiveQueue, searchQueue, projectionQueue} {
			select {
			case queue <- id:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	for _, id := range recovered {
		if err := enqueue(id); err != nil {
			return err
		}
	}
	statsDir := filepath.Join(opts.Spool, "stream-capture-stats")
	captureErr := discovery.CaptureStreamConfigured(ctx, opts.Interface, statsDir, source, allow, opts.Collection, journal, scope, func(id string) error {
		return enqueue(id)
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
	if captureErr != nil && !errors.Is(captureErr, context.Canceled) {
		return captureErr
	}
	return nil
}
