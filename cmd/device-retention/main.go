// device-retention previews seven-day retention by default. Apply is explicitly
// bounded and interruptible; schedule externally, outside the ingest process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"proxy-sentinel/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	apply := flag.Bool("apply", false, "delete after emitting the preview")
	batches := flag.Int("max-batches", 1, "maximum batches this invocation")
	batchSize := flag.Int("batch-size", 500, "rows per batch, at most 1000")
	maxDuration := flag.Duration("max-duration", 13*time.Minute, "invocation time budget, at most 13m to leave shutdown time before the service limit")
	flag.Parse()
	if *batches < 1 || *batchSize < 1 || *batchSize > 1000 || *maxDuration <= 0 || *maxDuration > 13*time.Minute {
		return fmt.Errorf("invalid maintenance bounds: max-batches must be positive, batch-size must be 1..1000, max-duration must be positive and at most 13m")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := store.NewPostgresStore(store.PostgresOptions{DSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")})
	if err != nil {
		return err
	}
	defer s.Close()
	return maintainRetention(ctx, s, retentionOptions{apply: *apply, batches: *batches, batchSize: *batchSize, maxDuration: *maxDuration}, json.NewEncoder(os.Stdout), realRetentionClock())
}

type retentionStore interface {
	PreviewDeviceRetention(context.Context, time.Time) (store.DeviceRetentionPreview, error)
	DeleteDeviceRetentionBatch(context.Context, time.Time, int) (int64, error)
}

type retentionOptions struct {
	apply       bool
	batches     int
	batchSize   int
	maxDuration time.Duration
}

type retentionClock struct {
	now  func() time.Time
	wait func(context.Context, time.Duration) error
}

func realRetentionClock() retentionClock {
	return retentionClock{now: time.Now, wait: func(ctx context.Context, duration time.Duration) error {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}}
}

// A bounded maintenance run can leave eligible work for the next timer. Its own
// budget is a planned stop; external cancellation and database errors are not.
func maintainRetention(parent context.Context, s retentionStore, options retentionOptions, enc *json.Encoder, clock retentionClock) error {
	deadline := clock.now().Add(options.maxDuration)
	ctx, stop := context.WithDeadline(parent, deadline)
	defer stop()
	completed := 0
	var deleted int64
	finish := func(reason, phase string, unconfirmed bool) error {
		return enc.Encode(map[string]any{"reason": reason, "phase": phase, "completed_batches": completed, "deleted_rows": deleted, "batch_outcome_unconfirmed": unconfirmed, "disk_space_reclaimed": "not_measured"})
	}
	budgetExpired := func() bool { return !clock.now().Before(deadline) || errors.Is(ctx.Err(), context.DeadlineExceeded) }
	handleError := func(err error, phase string, unconfirmed bool) error {
		if parent.Err() != nil {
			return parent.Err()
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
			return finish("time_budget_exhausted", phase, unconfirmed)
		}
		return err
	}
	previewCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	p, err := s.PreviewDeviceRetention(previewCtx, clock.now())
	cancel()
	if err != nil {
		if options.apply {
			return handleError(err, "preview", false)
		}
		return err
	}
	if err = enc.Encode(p); err != nil {
		return err
	}
	if !options.apply {
		return nil
	}
	effectiveSize := options.batchSize
	stableBatches := 0
	for i := 0; i < options.batches; i++ {
		if parent.Err() != nil {
			return parent.Err()
		}
		if budgetExpired() {
			return finish("time_budget_exhausted", "between_batches", false)
		}
		started := clock.now()
		var n int64
		retried := false
		for retry := 0; ; retry++ {
			if parent.Err() != nil {
				return parent.Err()
			}
			if budgetExpired() {
				return finish("time_budget_exhausted", "retry", false)
			}
			n, err = s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, effectiveSize)
			if err == nil {
				break
			}
			var noProgress *store.DeviceRetentionNoProgressError
			if errors.As(err, &noProgress) {
				if parent.Err() != nil {
					return parent.Err()
				}
				// This empty delete committed successfully, so its outcome is known even
				// when the invocation budget expires immediately afterwards.
				if budgetExpired() {
					return finish("time_budget_exhausted", "batch", false)
				}
				// Re-select after a reference race, but defer persistent locks to the next
				// timer rather than declaring the entire eligible history exhausted.
				if retry >= 2 {
					return finish("candidate_batch_deferred", "batch", false)
				}
			}
			if parent.Err() != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return handleError(err, "batch", true)
			}
			retried = true
			stableBatches = 0
			nextSize, reason, retryable := retentionRetry(err, effectiveSize)
			if retry >= 9 || !retryable {
				return err
			}
			effectiveSize = nextSize
			if e := enc.Encode(map[string]any{"batch": i + 1, "retry": retry + 1, "reason": reason, "batch_size": effectiveSize, "error": err.Error()}); e != nil {
				return e
			}
			if err = clock.wait(ctx, time.Second); err != nil {
				return handleError(err, "retry_wait", false)
			}
		}
		completed++
		deleted += n
		if err = enc.Encode(map[string]any{"batch": i + 1, "deleted": n, "batch_size": effectiveSize, "batch_millis": clock.now().Sub(started).Milliseconds(), "disk_space_reclaimed": "not_measured"}); err != nil {
			return err
		}
		if parent.Err() != nil {
			return parent.Err()
		}
		if n == 0 {
			return finish("no_eligible_snapshots", "complete", false)
		}
		if !retried {
			stableBatches++
		}
		// A transient I/O spike must not permanently reduce a long maintenance
		// run to single-row batches. Restore capacity slowly within its bound.
		if stableBatches >= 10 && effectiveSize < options.batchSize {
			effectiveSize = min(options.batchSize, max(effectiveSize+1, effectiveSize*5/4))
			stableBatches = 0
			if err = enc.Encode(map[string]any{"reason": "restore_batch_after_stable_commits", "next_batch_size": effectiveSize}); err != nil {
				return err
			}
		}
		if i+1 == options.batches {
			return finish("batch_limit_reached", "complete", false)
		}
		if err = clock.wait(ctx, time.Second); err != nil {
			return handleError(err, "between_batches", false)
		}
	}
	return finish("batch_limit_reached", "complete", false)
}

func retentionRetry(err error, size int) (int, string, bool) {
	var noProgress *store.DeviceRetentionNoProgressError
	if errors.As(err, &noProgress) {
		return size, "candidate_batch_changed_or_locked", true
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return size, "", false
	}
	if pgErr.Code == "55P03" {
		return size, "lock_busy", true
	}
	if pgErr.Code != "57014" {
		return size, "", false
	}
	var batch *store.DeviceRetentionBatchError
	if errors.As(err, &batch) {
		if batch.Rows == 1 {
			return size, "retry_single_snapshot", true
		}
		if batch.Rows > 1 {
			return max(1, min(size/2, batch.Rows/2)), "reduce_batch_after_statement_timeout", true
		}
	}
	if size > 1 {
		return max(1, size/2), "reduce_batch_after_statement_timeout", true
	}
	return size, "", false
}
