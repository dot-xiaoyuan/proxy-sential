package realtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"proxy-sentinel/internal/store"
	"proxy-sentinel/internal/streamlog"
)

type StreamRunOptions struct {
	Capture            Options
	MaxPendingSegments int
	DrainOnly          bool
	OnSourceError      func(Source, error)
}

// RunStream keeps source capture and segment consumption independent. Every
// source must already have an audited fresh cursor; this function never picks
// a cutoff or silently skips legacy input. A bounded in-memory channel is only
// backpressure: the immutable journal remains the recovery authority.
func RunStream(ctx context.Context, journal *streamlog.Journal, writer streamlog.Writer, opts StreamRunOptions) error {
	if journal == nil || writer == nil || opts.Capture.SensorID == "" || len(opts.Capture.Sources) == 0 {
		return errors.New("stream run requires journal, writer, sensor and sources")
	}
	if opts.Capture.PollInterval <= 0 {
		opts.Capture.PollInterval = 500 * time.Millisecond
	}
	if opts.Capture.StoreTimeout <= 0 {
		opts.Capture.StoreTimeout = 3 * time.Second
	}
	if opts.MaxPendingSegments <= 0 || opts.MaxPendingSegments > 64 {
		opts.MaxPendingSegments = 16
	}
	if opts.OnSourceError == nil {
		opts.OnSourceError = func(source Source, err error) {
			log.Printf("stream source error: kind=%q path=%q error=%v", source.Kind, source.Path, err)
		}
	}
	var rawMu sync.Mutex
	rawMissingSince := map[string]time.Time{}
	journal.SetRawResolver(func(segment streamlog.Segment) ([]byte, error) {
		raw, err := resolveZeekSourceRaw(segment)
		key := segment.SourcePath + "\x00" + segment.FileID + "\x00" + segment.RawSHA256
		rawMu.Lock()
		defer rawMu.Unlock()
		if err == nil {
			delete(rawMissingSince, key)
			return raw, nil
		}
		if errors.Is(err, ErrStreamArchivePending) {
			since := rawMissingSince[key]
			if since.IsZero() {
				rawMissingSince[key] = time.Now()
			} else if time.Since(since) >= 60*time.Second {
				return nil, ErrStreamSourceGap
			}
		}
		return nil, err
	})
	type sourceReady struct {
		source  Source
		ids     []string
		release func()
	}
	ready := make([]sourceReady, 0, len(opts.Capture.Sources))
	var startupFailures []error
	defer func() {
		for i := len(ready) - 1; i >= 0; i-- {
			ready[i].release()
		}
	}()
	seen := map[string]bool{}
	for _, source := range opts.Capture.Sources {
		if source.Kind == "" || source.Path == "" {
			return errors.New("stream source requires kind and path")
		}
		key := source.Kind + "\x00" + source.Path
		if seen[key] {
			return fmt.Errorf("duplicate stream source %s at %s", source.Kind, source.Path)
		}
		seen[key] = true
		release, err := journal.AcquireSourceLease(source.Kind, source.Path)
		if err != nil {
			return err
		}
		ready = append(ready, sourceReady{source: source, release: release})
		ids, err := journal.RecoverSource(source.Kind, source.Path)
		if err != nil {
			if streamPermanentError(err) {
				wrapped := fmt.Errorf("recover stream source %s at %s: %w", source.Kind, source.Path, err)
				opts.OnSourceError(source, wrapped)
				startupFailures = append(startupFailures, wrapped)
				release()
				ready = ready[:len(ready)-1]
				continue
			}
			return fmt.Errorf("recover stream source %s at %s: %w", source.Kind, source.Path, err)
		}
		ready[len(ready)-1].ids = ids
	}
	if len(ready) == 0 {
		return errors.Join(startupFailures...)
	}
	results := make(chan error, len(ready))
	var workers sync.WaitGroup
	for _, item := range ready {
		workers.Add(1)
		go func(item sourceReady) {
			defer workers.Done()
			err := runStreamSource(ctx, journal, writer, opts, item.source, item.ids)
			if err != nil && ctx.Err() == nil {
				opts.OnSourceError(item.source, err)
			}
			results <- err
		}(item)
	}
	remaining := len(ready)
	var failures []error
	for remaining > 0 {
		select {
		case <-ctx.Done():
			workers.Wait()
			return nil
		case err := <-results:
			remaining--
			if err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func runStreamSource(ctx context.Context, journal *streamlog.Journal, writer streamlog.Writer, opts StreamRunOptions, source Source, recovered []string) error {
	sourceCtx, cancel := context.WithCancel(ctx)
	var drainWorker sync.WaitGroup
	defer func() { cancel(); drainWorker.Wait() }()
	var reportMu sync.Mutex
	var lastReport time.Time
	reportTransient := func(err error) {
		reportMu.Lock()
		defer reportMu.Unlock()
		if time.Since(lastReport) < 30*time.Second {
			return
		}
		lastReport = time.Now()
		opts.OnSourceError(source, err)
	}
	// Each lane preserves source order, while projection can advance past a
	// segment whose independent ClickHouse archive or search is still pending.
	// A permit is returned only after finalization, bounding durable in-flight
	// segments as well as memory. Recovery uses the same bound and lane order.
	queues := map[streamlog.Lane]chan string{
		streamlog.Archive: make(chan string, opts.MaxPendingSegments), streamlog.Search: make(chan string, opts.MaxPendingSegments),
		streamlog.Projection: make(chan string, opts.MaxPendingSegments),
	}
	finalize := make(chan string, opts.MaxPendingSegments)
	permits := make(chan struct{}, opts.MaxPendingSegments)
	workerErrors := make(chan error, len(queues)+1)
	processor := streamlog.Processor{Journal: journal, Writer: writer, SinkTimeout: opts.Capture.StoreTimeout}
	startWorker := func(queue <-chan string, name string, run func(context.Context, string) error, release bool) {
		drainWorker.Add(1)
		go func() {
			defer drainWorker.Done()
			for {
				var id string
				select {
				case <-sourceCtx.Done():
					return
				case id = <-queue:
				}
				for {
					// The processor starts the unchanged storage budget at the
					// actual database call. Journal fsync and source rehydration
					// are outside that budget; the site no-progress guard still
					// stops a stalled source without stealing RPC time.
					err := run(sourceCtx, id)
					if err == nil {
						if release {
							<-permits
						}
						break
					}
					if sourceCtx.Err() != nil {
						return
					}
					if streamPermanentError(err) {
						workerErrors <- fmt.Errorf("stream %s segment %s: %w", name, id, err)
						return
					}
					if !errors.Is(err, streamlog.ErrUnconfirmed) {
						reportTransient(fmt.Errorf("retry stream %s segment %s: %w", name, id, err))
					}
					if !waitStreamPoll(sourceCtx, opts.Capture.PollInterval) {
						return
					}
				}
			}
		}()
	}
	for lane, queue := range queues {
		lane := lane
		startWorker(queue, string(lane), func(ctx context.Context, id string) error {
			return processor.DrainLane(ctx, id, lane)
		}, false)
	}
	drainWorker.Add(1)
	go func() {
		defer drainWorker.Done()
		if err := runStreamFinalizer(sourceCtx, finalize, opts.Capture.PollInterval,
			processor.FinalizeAfterLanes, func(string) { <-permits }, reportTransient); err != nil {
			workerErrors <- fmt.Errorf("stream finalize: %w", err)
		}
	}()
	enqueue := func(id string) error {
		for _, queue := range []chan string{queues[streamlog.Archive], queues[streamlog.Projection], queues[streamlog.Search], finalize} {
			select {
			case queue <- id:
			case err := <-workerErrors:
				return err
			case <-sourceCtx.Done():
				return sourceCtx.Err()
			}
		}
		return nil
	}
	acquire := func() error {
		select {
		case permits <- struct{}{}:
			return nil
		case err := <-workerErrors:
			return err
		case <-sourceCtx.Done():
			return sourceCtx.Err()
		}
	}
	for _, id := range recovered {
		if err := acquire(); err != nil {
			return err
		}
		if err := enqueue(id); err != nil {
			return err
		}
	}
	if opts.DrainOnly {
		for len(permits) != 0 {
			select {
			case err := <-workerErrors:
				return err
			case <-sourceCtx.Done():
				return sourceCtx.Err()
			case <-time.After(opts.Capture.PollInterval):
			}
		}
		return nil
	}
	var archivePendingSince time.Time
	var smallZeekBatchSince time.Time
	for {
		select {
		case err := <-workerErrors:
			return err
		default:
		}
		if err := acquire(); err != nil {
			return err
		}
		if source.Kind == "zeek-dhcp-binding" {
			cursor, cursorErr := journal.LoadSource(source.Kind, source.Path)
			current, statErr := os.Stat(source.Path)
			if cursorErr == nil && statErr == nil && fileIdentity(source.Path, current) == cursor.FileID {
				lag := current.Size() - cursor.Offset
				if holdSmallZeekBindingBatch(lag, &smallZeekBatchSince, time.Now()) {
					<-permits
					if !waitStreamPoll(sourceCtx, opts.Capture.PollInterval) {
						return nil
					}
					continue
				}
			} else {
				// A rotated file must be resolved immediately so its old inode and
				// compressed archive remain part of the continuous source proof.
				smallZeekBatchSince = time.Time{}
			}
		}
		id, captured, err := CaptureStreamOnce(sourceCtx, journal, opts.Capture, source)
		if err != nil {
			<-permits
			if sourceCtx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrStreamArchivePending) {
				if archivePendingSince.IsZero() {
					archivePendingSince = time.Now()
				}
				if time.Since(archivePendingSince) >= 60*time.Second {
					return fmt.Errorf("Zeek archive not verifiable after 60 seconds: %w", ErrStreamSourceGap)
				}
			} else {
				archivePendingSince = time.Time{}
			}
			if streamPermanentError(err) {
				return err
			}
			reportTransient(fmt.Errorf("retry stream capture: %w", err))
			if !waitStreamPoll(sourceCtx, opts.Capture.PollInterval) {
				return nil
			}
			continue
		}
		archivePendingSince = time.Time{}
		if captured {
			smallZeekBatchSince = time.Time{}
			if err := enqueue(id); err != nil {
				return err
			}
			continue
		}
		<-permits
		if !waitStreamPoll(sourceCtx, opts.Capture.PollInterval) {
			return nil
		}
	}
}

// Coalescing a small, still-growing Zeek file for at most two seconds avoids
// one full set of mechanical-disk fsyncs per handful of DHCP bindings. The
// retained source file remains the recovery authority; a full backlog or
// rotation is never held. This changes admission timing, not sink budgets.
func holdSmallZeekBindingBatch(lag int64, first *time.Time, now time.Time) bool {
	const targetBytes = 16 << 10
	const maxHold = 2 * time.Second
	if lag <= 0 || lag >= targetBytes {
		*first = time.Time{}
		return false
	}
	if first.IsZero() {
		*first = now
	}
	return now.Sub(*first) < maxHold
}

func streamPermanentError(err error) bool {
	return errors.Is(err, ErrStreamSourceGap) || errors.Is(err, streamlog.ErrQuarantined) ||
		errors.Is(err, streamlog.ErrContentConflict) || errors.Is(err, store.ErrStreamProjectorUnavailable)
}

func waitStreamPoll(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
