package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"proxy-sentinel/internal/store"
)

type retentionReplay struct {
	preview func(context.Context) (store.DeviceRetentionPreview, error)
	delete  func(context.Context, time.Time, int) (int64, error)
}

func (r retentionReplay) PreviewDeviceRetention(ctx context.Context, _ time.Time) (store.DeviceRetentionPreview, error) {
	return r.preview(ctx)
}
func (r retentionReplay) DeleteDeviceRetentionBatch(ctx context.Context, cutoff time.Time, size int) (int64, error) {
	return r.delete(ctx, cutoff, size)
}

func TestRetentionBudgetPreservesCommittedBatches(t *testing.T) {
	base := time.Now()
	now := base
	cutoff := base.Add(-7 * 24 * time.Hour)
	calls := 0
	r := retentionReplay{
		preview: func(context.Context) (store.DeviceRetentionPreview, error) {
			return store.DeviceRetentionPreview{Cutoff: cutoff}, nil
		},
		delete: func(ctx context.Context, got time.Time, size int) (int64, error) {
			calls++
			if got != cutoff || size != 500 {
				t.Fatal("batch lost its frozen cutoff or bound", got, size)
			}
			if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(base.Add(time.Minute)) {
				t.Fatal("database operation has no invocation deadline", deadline)
			}
			now = now.Add(40 * time.Second)
			return 7, nil
		},
	}
	var out bytes.Buffer
	err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), retentionClock{
		now:  func() time.Time { return now },
		wait: func(context.Context, time.Duration) error { now = now.Add(time.Second); return nil },
	})
	if err != nil || calls != 2 || !strings.Contains(out.String(), `"completed_batches":2`) || !strings.Contains(out.String(), `"deleted_rows":14`) || !strings.Contains(out.String(), `"reason":"time_budget_exhausted"`) {
		t.Fatalf("committed work must be recorded once, then stop before a third batch: calls=%d err=%v\n%s", calls, err, out.String())
	}
}

func TestRetentionBudgetCancelsBlockedBatchWithoutClaimingDeletion(t *testing.T) {
	var out bytes.Buffer
	r := retentionReplay{
		preview: func(context.Context) (store.DeviceRetentionPreview, error) {
			return store.DeviceRetentionPreview{}, nil
		},
		delete: func(ctx context.Context, _ time.Time, _ int) (int64, error) { <-ctx.Done(); return 9, ctx.Err() },
	}
	err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: 5 * time.Millisecond}, json.NewEncoder(&out), realRetentionClock())
	if err != nil || !strings.Contains(out.String(), `"deleted_rows":0`) || !strings.Contains(out.String(), `"batch_outcome_unconfirmed":true`) || !strings.Contains(out.String(), `"phase":"batch"`) {
		t.Fatalf("a timed-out commit is not an acknowledged deletion: %v\n%s", err, out.String())
	}
}

func TestRetentionBudgetDoesNotMaskRealFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"bad reference", &pgconn.PgError{Code: "22P02", Message: "invalid case IP"}},
		{"ordinary query deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			r := retentionReplay{
				preview: func(context.Context) (store.DeviceRetentionPreview, error) {
					return store.DeviceRetentionPreview{}, nil
				},
				delete: func(context.Context, time.Time, int) (int64, error) { return 0, tc.err },
			}
			err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), realRetentionClock())
			if !errors.Is(err, tc.err) || strings.Contains(out.String(), "time_budget_exhausted") {
				t.Fatal("real failure was converted to planned maintenance completion", err, out.String())
			}
		})
	}
}

func TestRetentionParentCancellationIsFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	r := retentionReplay{
		preview: func(context.Context) (store.DeviceRetentionPreview, error) {
			return store.DeviceRetentionPreview{}, nil
		},
		delete: func(context.Context, time.Time, int) (int64, error) { cancel(); return 0, context.Canceled },
	}
	err := maintainRetention(ctx, r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), realRetentionClock())
	if !errors.Is(err, context.Canceled) || strings.Contains(out.String(), "time_budget_exhausted") {
		t.Fatal("SIGTERM/parent cancellation must remain visible", err, out.String())
	}
}

func TestRetentionBudgetEndsRetryWait(t *testing.T) {
	base := time.Now()
	now := base
	calls := 0
	var out bytes.Buffer
	r := retentionReplay{
		preview: func(context.Context) (store.DeviceRetentionPreview, error) {
			return store.DeviceRetentionPreview{}, nil
		},
		delete: func(context.Context, time.Time, int) (int64, error) {
			calls++
			return 0, &pgconn.PgError{Code: "55P03"}
		},
	}
	err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), retentionClock{
		now:  func() time.Time { return now },
		wait: func(context.Context, time.Duration) error { now = base.Add(time.Minute); return nil },
	})
	if err != nil || calls != 1 || !strings.Contains(out.String(), `"phase":"retry"`) || !strings.Contains(out.String(), `"completed_batches":0`) {
		t.Fatal("budget must also stop retry loops", calls, err, out.String())
	}
}

func TestRetentionPreviewRemainsReadOnly(t *testing.T) {
	calls := 0
	var out bytes.Buffer
	r := retentionReplay{
		preview: func(context.Context) (store.DeviceRetentionPreview, error) {
			return store.DeviceRetentionPreview{}, nil
		},
		delete: func(context.Context, time.Time, int) (int64, error) { calls++; return 1, nil },
	}
	err := maintainRetention(context.Background(), r, retentionOptions{batches: 1, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), realRetentionClock())
	if err != nil || calls != 0 || strings.Contains(out.String(), "completed_batches") {
		t.Fatal("preview must not delete", calls, err, out.String())
	}
}

func TestRetentionBudgetIncludesPreview(t *testing.T) {
	base := time.Now()
	now := base
	calls := 0
	var out bytes.Buffer
	r := retentionReplay{
		preview: func(context.Context) (store.DeviceRetentionPreview, error) {
			now = base.Add(time.Minute)
			return store.DeviceRetentionPreview{}, nil
		},
		delete: func(context.Context, time.Time, int) (int64, error) { calls++; return 1, nil },
	}
	err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), retentionClock{now: func() time.Time { return now }})
	if err != nil || calls != 0 || !strings.Contains(out.String(), `"completed_batches":0`) || !strings.Contains(out.String(), `"reason":"time_budget_exhausted"`) {
		t.Fatal("preview must consume the same budget before any deletion", calls, err, out.String())
	}
}

func TestRetentionParentCancellationAfterCommitStillFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	r := retentionReplay{
		preview: func(context.Context) (store.DeviceRetentionPreview, error) {
			return store.DeviceRetentionPreview{}, nil
		},
		delete: func(context.Context, time.Time, int) (int64, error) { cancel(); return 3, nil },
	}
	err := maintainRetention(ctx, r, retentionOptions{apply: true, batches: 1, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), realRetentionClock())
	if !errors.Is(err, context.Canceled) || !strings.Contains(out.String(), `"deleted":3`) || strings.Contains(out.String(), "time_budget_exhausted") {
		t.Fatal("record acknowledged commits but preserve external cancellation", err, out.String())
	}
}

func TestRetentionNoProgressDefersWithoutClaimingExhaustion(t *testing.T) {
	base := time.Now()
	now := base
	calls := 0
	var out bytes.Buffer
	r := retentionReplay{preview: func(context.Context) (store.DeviceRetentionPreview, error) {
		return store.DeviceRetentionPreview{}, nil
	}, delete: func(context.Context, time.Time, int) (int64, error) {
		calls++
		if calls == 1 {
			return 2, nil
		}
		return 0, &store.DeviceRetentionNoProgressError{Candidates: 1}
	}}
	err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), retentionClock{now: func() time.Time { return now }, wait: func(context.Context, time.Duration) error { now = now.Add(time.Second); return nil }})
	if err != nil || calls != 4 || !strings.Contains(out.String(), `"reason":"candidate_batch_deferred"`) || !strings.Contains(out.String(), `"completed_batches":1`) || !strings.Contains(out.String(), `"deleted_rows":2`) || !strings.Contains(out.String(), `"batch_outcome_unconfirmed":false`) || strings.Contains(out.String(), "no_eligible_snapshots") {
		t.Fatal(calls, err, out.String())
	}
}
func TestRetentionNoProgressRecomputesCandidatesAndRecovers(t *testing.T) {
	calls := 0
	var out bytes.Buffer
	r := retentionReplay{preview: func(context.Context) (store.DeviceRetentionPreview, error) {
		return store.DeviceRetentionPreview{}, nil
	}, delete: func(_ context.Context, _ time.Time, size int) (int64, error) {
		calls++
		if size != 500 {
			t.Fatal("changed candidates must not shrink the physical batch bound", size)
		}
		if calls == 1 {
			return 0, &store.DeviceRetentionNoProgressError{Candidates: 3}
		}
		if calls == 2 {
			return 1, nil
		}
		return 0, nil
	}}
	err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 2, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), retentionClock{now: time.Now, wait: func(context.Context, time.Duration) error { return nil }})
	if err != nil || calls != 3 || !strings.Contains(out.String(), `"reason":"no_eligible_snapshots"`) || !strings.Contains(out.String(), `"deleted_rows":1`) || !strings.Contains(out.String(), "candidate_batch_changed_or_locked") {
		t.Fatal(calls, err, out.String())
	}
}
func TestRetentionNoProgressCommitAtBudgetIsConfirmed(t *testing.T) {
	base := time.Now()
	now := base
	var out bytes.Buffer
	r := retentionReplay{preview: func(context.Context) (store.DeviceRetentionPreview, error) {
		return store.DeviceRetentionPreview{}, nil
	}, delete: func(context.Context, time.Time, int) (int64, error) {
		now = base.Add(time.Minute)
		return 0, &store.DeviceRetentionNoProgressError{Candidates: 1}
	}}
	err := maintainRetention(context.Background(), r, retentionOptions{apply: true, batches: 120, batchSize: 500, maxDuration: time.Minute}, json.NewEncoder(&out), retentionClock{now: func() time.Time { return now }, wait: func(context.Context, time.Duration) error { t.Fatal("expired budget must not retry"); return nil }})
	if err != nil || !strings.Contains(out.String(), `"reason":"time_budget_exhausted"`) || !strings.Contains(out.String(), `"batch_outcome_unconfirmed":false`) {
		t.Fatal(err, out.String())
	}
}
