package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// The schema and its progress trigger must be installed and verified before
// explicitly enabling this path. Missing schema is reported, never silently
// redirected back to the expensive global claim query.
func identityDerivedReadyEnabled() bool {
	return os.Getenv("PROXY_SENTINEL_IDENTITY_DERIVED_READY") == "true"
}

func (s *DBStore) runIdentityFragmentDerivedReady(ctx context.Context) {
	scannerDone := make(chan struct{})
	statusDone := make(chan struct{})
	go func() {
		defer close(scannerDone)
		s.runIdentityDerivedReadyScanner(ctx)
	}()
	go func() {
		defer close(statusDone)
		s.runIdentityDerivedReadyStatus(ctx)
	}()
	defer func() { <-scannerDone; <-statusDone }()
	scheduler := identityDerivedReadyScheduler{claim: s.pg.claimIdentityDerivedReady}
	for ctx.Err() == nil {
		// Keep the existing shared primary-inbox resource gate until a measured
		// realtime budget can safely replace it. This may still miss 5 seconds.
		if s.deferIdentityDerivedWorkWithQuota(ctx) {
			continue
		}
		work, cancel := context.WithTimeout(ctx, identityWorkBudget)
		err := s.projectIdentityFragmentDerivedWithClaim(work, scheduler.next)
		cancel()
		delay := 20 * time.Millisecond
		switch {
		case errors.Is(err, sql.ErrNoRows):
			delay = time.Second
		case errors.Is(err, errIdentityDerivedReadyDeferred):
			// A stale key was cleaned or a live older lease rescheduled.
		case err != nil:
			if ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "identity derived ready:", err)
			}
			delay = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (s *DBStore) runIdentityDerivedReadyStatus(ctx context.Context) {
	var lastErrorReport time.Time
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := s.pg.publishIdentityDerivedReadyStatus(work)
		cancel()
		if err != nil && ctx.Err() == nil && time.Since(lastErrorReport) >= 30*time.Second {
			fmt.Fprintln(os.Stderr, "identity derived ready status:", err)
			lastErrorReport = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func (s *DBStore) runIdentityDerivedReadyScanner(ctx context.Context) {
	var lastErrorReport, lastProgressReport time.Time
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		page, err := s.pg.scanIdentityDerivedReadyPage(work, 256)
		cancel()
		if err == nil && page.Done {
			fmt.Fprintln(os.Stderr, "identity derived ready pending-key scan completed")
			return
		}
		if err == nil && !page.Deferred && time.Since(lastProgressReport) >= 30*time.Second {
			fmt.Fprintf(os.Stderr, "identity derived ready scan page scanned=%d eligible=%d\n", page.Scanned, page.Eligible)
			lastProgressReport = time.Now()
		}
		delay := time.Second
		if err != nil {
			delay = 5 * time.Second
			if ctx.Err() == nil && time.Since(lastErrorReport) >= 30*time.Second {
				fmt.Fprintln(os.Stderr, "identity derived ready pending-key scan:", err)
				lastErrorReport = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}
