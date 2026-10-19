package store

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// sharedProfileBeaconInterval is how often the runtime row is refreshed. It matches the old idle
// heartbeat cadence, so status readers see the same freshness as before.
const sharedProfileBeaconInterval = 5 * time.Second

// sharedProfileBeacon accumulates runtime status in memory. Writing it per job made every worker
// queue on the single runtime row; now one flush per interval writes the totals.
type sharedProfileBeacon struct {
	mu          sync.Mutex
	pendingJobs int64
	lastError   string
	errorDirty  bool
}

// success counts one finished job and clears a pending error.
func (b *sharedProfileBeacon) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pendingJobs++
	if b.lastError != "" {
		b.lastError = ""
		b.errorDirty = true
	}
}

// failure records the latest error; the flush writes the newest one.
func (b *sharedProfileBeacon) failure(text string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastError = text
	b.errorDirty = true
}

// take returns the pending counts and resets them. The error is reported only when it changed.
func (b *sharedProfileBeacon) take() (int64, string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	jobs, changed := b.pendingJobs, b.errorDirty
	b.pendingJobs, b.errorDirty = 0, false
	return jobs, b.lastError, changed
}

// restore puts back what a failed flush took, unless something newer arrived meanwhile.
func (b *sharedProfileBeacon) restore(jobs int64, text string, changed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pendingJobs += jobs
	if changed && !b.errorDirty {
		b.lastError = text
		b.errorDirty = true
	}
}

// flushSharedProfileBeacon writes the accumulated state in one short statement. It does not wait
// for the WAL flush, because the counter is advisory.
func (s *PostgresStore) flushSharedProfileBeacon(ctx context.Context) error {
	jobs, text, changed := s.profileBeacon.take()
	err := s.writeAdvisoryState(ctx, `UPDATE shared_device_profile_runtime SET last_success_at=now(),processed_jobs=processed_jobs+$1,last_error=CASE WHEN $3 THEN $2 ELSE last_error END,updated_at=now() WHERE singleton`, jobs, text, changed)
	if err != nil {
		s.profileBeacon.restore(jobs, text, changed)
	}
	return err
}

// runSharedProfileBeacon flushes on a fixed interval, including when idle, so last_success_at keeps
// showing liveness. A final flush on shutdown keeps the counts.
func (s *PostgresStore) runSharedProfileBeacon(ctx context.Context) {
	ticker := time.NewTicker(sharedProfileBeaconInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.flushSharedProfileBeacon(final)
			cancel()
			return
		case <-ticker.C:
			work, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := s.flushSharedProfileBeacon(work); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "shared device profile beacon:", err)
			}
			cancel()
		}
	}
}
