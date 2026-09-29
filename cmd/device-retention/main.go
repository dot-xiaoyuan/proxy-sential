// device-retention previews seven-day retention by default. Apply is explicitly
// bounded and interruptible; schedule externally, outside the ingest process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	flag.Parse()
	if *batches < 1 || *batchSize < 1 || *batchSize > 1000 {
		return fmt.Errorf("invalid batch bounds")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := store.NewPostgresStore(store.PostgresOptions{DSN: os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")})
	if err != nil {
		return err
	}
	defer s.Close()
	previewCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	p, err := s.PreviewDeviceRetention(previewCtx, time.Now())
	cancel()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	if err = enc.Encode(p); err != nil {
		return err
	}
	if !*apply {
		return nil
	}
	effectiveSize := *batchSize
	stableBatches := 0
	for i := 0; i < *batches; i++ {
		started := time.Now()
		var n int64
		retried := false
		for retry := 0; ; retry++ {
			n, err = s.DeleteDeviceRetentionBatch(ctx, p.Cutoff, effectiveSize)
			if err == nil {
				break
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
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if err = enc.Encode(map[string]any{"batch": i + 1, "deleted": n, "batch_size": effectiveSize, "batch_millis": time.Since(started).Milliseconds(), "disk_space_reclaimed": "not_measured"}); err != nil {
			return err
		}
		if n == 0 {
			break
		}
		if !retried {
			stableBatches++
		}
		// A transient I/O spike must not permanently reduce a long maintenance
		// run to single-row batches. Restore capacity slowly within its bound.
		if stableBatches >= 10 && effectiveSize < *batchSize {
			effectiveSize = min(*batchSize, max(effectiveSize+1, effectiveSize*5/4))
			stableBatches = 0
			if err = enc.Encode(map[string]any{"reason": "restore_batch_after_stable_commits", "next_batch_size": effectiveSize}); err != nil {
				return err
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func retentionRetry(err error, size int) (int, string, bool) {
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
