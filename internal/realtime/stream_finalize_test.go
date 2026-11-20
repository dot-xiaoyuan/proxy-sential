package realtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestStreamFinalizerDoesNotHoldReadySegmentBehindUnconfirmedSegment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := make(chan string, 2)
	queue <- "earlier"
	queue <- "ready"
	completed := make(chan string, 2)
	done := make(chan error, 1)
	go func() {
		done <- runStreamFinalizer(ctx, queue, time.Millisecond, func(_ context.Context, id string) error {
			if id == "earlier" {
				return streamlog.ErrUnconfirmed
			}
			return nil
		}, func(id string) { completed <- id }, func(error) {})
	}()
	select {
	case id := <-completed:
		if id != "ready" {
			t.Fatalf("completed %q before the ready segment", id)
		}
	case <-time.After(time.Second):
		t.Fatal("ready segment was held behind an unrelated unconfirmed segment")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestStreamFinalizerBacksOffStorageErrorsWithoutHoldingReadyWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	queue := make(chan string, 2)
	queue <- "storage-timeout"
	queue <- "ready"
	completed, done := make(chan string, 1), make(chan error, 1)
	var attempts atomic.Int32
	go func() {
		done <- runStreamFinalizer(ctx, queue, time.Millisecond, func(_ context.Context, id string) error {
			if id == "storage-timeout" {
				attempts.Add(1)
				return context.DeadlineExceeded
			}
			return nil
		}, func(id string) { completed <- id }, func(error) {})
	}()
	select {
	case id := <-completed:
		if id != "ready" {
			t.Fatalf("completed %q", id)
		}
	case <-ctx.Done():
		t.Fatal("ready work was delayed by a storage timeout")
	}
	time.Sleep(25 * time.Millisecond)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("retried failed storage without waiting: %d attempts", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStreamFinalizerParkedSegmentKeepsItsPermit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	queue := make(chan string, 2)
	queue <- "parked"
	queue <- "ready"
	completed, done := make(chan string, 2), make(chan error, 1)
	go func() {
		done <- runStreamFinalizer(ctx, queue, time.Millisecond, func(_ context.Context, id string) error {
			if id == "parked" {
				return errStreamFinalizationParked
			}
			return nil
		}, func(id string) { completed <- id }, func(error) {})
	}()
	select {
	case id := <-completed:
		if id != "ready" {
			t.Fatalf("released the parked segment: %q", id)
		}
	case <-ctx.Done():
		t.Fatal("ready segment could not finalize")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
