package realtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

type failureCleanupBackend struct {
	fakeBackend
	cleanupBudget   time.Duration
	cleanupCanceled bool
}

func (b *failureCleanupBackend) FailIngestBatch(ctx context.Context, _ string, _ error) error {
	deadline, ok := ctx.Deadline()
	if ok {
		b.cleanupBudget = time.Until(deadline)
	}
	b.cleanupCanceled = ctx.Err() != nil
	return errors.New("audit storage unavailable")
}
func TestFailedBatchAuditHasBoundedDetachedContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(rotationDNS("10.0.0.1")), 0600); err != nil {
		t.Fatal(err)
	}
	for _, timeout := range []time.Duration{time.Minute, 50 * time.Millisecond} {
		cause := errors.New("event storage unavailable")
		backend := &failureCleanupBackend{fakeBackend: fakeBackend{writeEventErr: cause}}
		err := ProcessOnce(context.Background(), backend, Options{SensorID: "cleanup", MaxBatchBytes: 1 << 20, StoreTimeout: timeout}, Source{Kind: "suricata", Path: path})
		if !errors.Is(err, cause) {
			t.Fatalf("audit error replaced original failure: %v", err)
		}
		limit := timeout
		if limit > 5*time.Second {
			limit = 5 * time.Second
		}
		if backend.cleanupBudget <= 0 || backend.cleanupBudget > limit || backend.cleanupCanceled {
			t.Fatalf("unbounded or canceled audit context: budget=%s canceled=%v", backend.cleanupBudget, backend.cleanupCanceled)
		}
		if backend.found {
			t.Fatal("failed batch advanced checkpoint")
		}
	}
}

type canceledWriteBackend struct {
	failureCleanupBackend
	cancel context.CancelFunc
}

func (b *canceledWriteBackend) WriteNormalizedEvents(context.Context, []normalized.Event) error {
	b.cancel()
	return context.Canceled
}
func TestFailedBatchAuditSurvivesParentCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(rotationDNS("10.0.0.1")), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &canceledWriteBackend{cancel: cancel}
	err := ProcessOnce(ctx, b, Options{SensorID: "cleanup", MaxBatchBytes: 1 << 20, StoreTimeout: time.Second}, Source{Kind: "suricata", Path: path})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation changed: %v", err)
	}
	if b.cleanupCanceled || b.cleanupBudget <= 0 || b.cleanupBudget > time.Second {
		t.Fatalf("failed audit reused canceled context: canceled=%v budget=%s", b.cleanupCanceled, b.cleanupBudget)
	}
	if b.found {
		t.Fatal("canceled write advanced checkpoint")
	}
}
