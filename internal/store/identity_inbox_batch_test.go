package store

import (
	"errors"
	"testing"
	"time"
)

// Per-batch cost is mostly fixed, so the controller must never starve the inbox by
// collapsing to tiny batches, and must recover quickly once the disk is fast again.
func TestInboxBatchSizeKeepsFloorAndRecovers(t *testing.T) {
	stable, size := 0, identityInboxBatchMax
	for i := 0; i < 20; i++ {
		size = nextInboxBatchSize(size, time.Second, errors.New("timeout"), &stable)
	}
	if size != identityInboxBatchMin {
		t.Fatalf("failures collapsed batch to %d", size)
	}
	for i := 0; i < 20 && size < identityInboxBatchMax; i++ {
		size = nextInboxBatchSize(size, 500*time.Millisecond, nil, &stable)
	}
	if size != identityInboxBatchMax {
		t.Fatalf("fast successes did not recover batch size: %d", size)
	}
	if identityInboxLease <= 2*identityInboxWorkBudget {
		t.Fatalf("lease %s does not cover claim plus apply budgets", identityInboxLease)
	}
}
