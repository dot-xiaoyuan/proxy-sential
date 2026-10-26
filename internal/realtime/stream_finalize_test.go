package realtime

import (
	"context"
	"errors"
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
