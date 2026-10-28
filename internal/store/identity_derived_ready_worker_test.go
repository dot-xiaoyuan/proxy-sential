package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestIdentityDerivedReadyWorkerIsExplicitlyOptIn(t *testing.T) {
	for _, tc := range []struct {
		value   string
		enabled bool
	}{{"", false}, {"false", false}, {"TRUE", false}, {"true", true}} {
		t.Setenv("PROXY_SENTINEL_IDENTITY_DERIVED_READY", tc.value)
		if got := identityDerivedReadyEnabled(); got != tc.enabled {
			t.Fatalf("value %q enabled=%v", tc.value, got)
		}
	}
}

func TestIdentityDerivedProjectionUsesSelectedClaimAndKeepsEmptyQueueVisible(t *testing.T) {
	calls := 0
	claim := func(context.Context) (identityExportFragment, error) {
		calls++
		return identityExportFragment{}, sql.ErrNoRows
	}
	err := (&DBStore{}).projectIdentityFragmentDerivedWithClaim(context.Background(), claim)
	if !errors.Is(err, sql.ErrNoRows) || calls != 1 {
		t.Fatalf("selected claim not used or no rows hidden: calls=%d err=%v", calls, err)
	}
}

func TestIdentityDerivedProjectionDoesNotReportUnclaimedDeferredWork(t *testing.T) {
	claim := func(context.Context) (identityExportFragment, error) {
		return identityExportFragment{}, errIdentityDerivedReadyDeferred
	}
	if err := (&DBStore{}).projectIdentityFragmentDerivedWithClaim(context.Background(), claim); !errors.Is(err, errIdentityDerivedReadyDeferred) {
		t.Fatalf("deferred key was hidden or reported as a claimed fragment: %v", err)
	}
}

func TestIdentityDerivedReadyWorkerStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { (&DBStore{}).runIdentityFragmentDerivedReady(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled worker or scanner did not stop")
	}
}
