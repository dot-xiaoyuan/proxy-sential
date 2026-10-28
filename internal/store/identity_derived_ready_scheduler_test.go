package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestIdentityDerivedReadySchedulerSharesWorkAndUsesIdleCapacity(t *testing.T) {
	var calls []int
	scheduler := identityDerivedReadyScheduler{claim: func(_ context.Context, priority int) (identityExportFragment, error) {
		calls = append(calls, priority)
		return identityExportFragment{First: priority}, nil
	}}
	for i, want := range []int{0, 0, 0, 1, 0, 0, 0, 1} {
		fragment, err := scheduler.next(context.Background())
		if err != nil || fragment.First != want {
			t.Fatalf("turn %d got %+v %v", i, fragment, err)
		}
	}
	if len(calls) != 8 {
		t.Fatalf("unexpected claims: %v", calls)
	}

	calls = nil
	scheduler = identityDerivedReadyScheduler{claim: func(_ context.Context, priority int) (identityExportFragment, error) {
		calls = append(calls, priority)
		if priority == 0 {
			return identityExportFragment{}, sql.ErrNoRows
		}
		return identityExportFragment{First: 1}, nil
	}}
	fragment, err := scheduler.next(context.Background())
	if err != nil || fragment.First != 1 || len(calls) != 2 || calls[0] != 0 || calls[1] != 1 {
		t.Fatalf("idle priority did not yield: %+v %v %v", fragment, err, calls)
	}
}

func TestIdentityDerivedReadySchedulerDoesNotHideClaimFailures(t *testing.T) {
	failure := errors.New("database unavailable")
	calls := 0
	scheduler := identityDerivedReadyScheduler{claim: func(_ context.Context, priority int) (identityExportFragment, error) {
		calls++
		return identityExportFragment{}, failure
	}}
	_, err := scheduler.next(context.Background())
	if !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("failure hidden: %v calls=%d", err, calls)
	}
}
