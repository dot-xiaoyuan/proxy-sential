package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// A segment is finalized after all three lane notifications. Transient errors
// remain on a bounded retry schedule; at most two finalizations run at once so
// one slow segment cannot block all later segments. Journal is the durable
// recovery source after cancellation or restart.
type passiveFinalizerSignal struct {
	id   string
	lane streamlog.Lane
}

type passiveFinalizerResult struct {
	id  string
	err error
}

// Wrapped cancellation is routine shutdown, but a joined disk/sink error must
// survive cancellation. errors.Is alone would also hide that joined failure.
func passiveCancellationOnly(err error) bool {
	if err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !passiveCancellationOnly(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return passiveCancellationOnly(wrapped.Unwrap())
	}
	return false
}

func runPassiveFinalizer(ctx context.Context, queue <-chan passiveFinalizerSignal, finalize func(context.Context, string) error, retryDelay time.Duration, maxRetries int) (resultErr error) {
	if retryDelay <= 0 || maxRetries <= 0 {
		return errors.New("invalid passive finalizer retry budget")
	}
	workCtx, cancel := context.WithCancel(ctx)
	const maxConcurrent = 2
	results := make(chan passiveFinalizerResult, maxConcurrent)
	signals := map[string]uint8{}
	retries := map[string]time.Time{}
	running := map[string]bool{}
	defer func() {
		cancel()
		// Join the bounded in-flight calls before the caller closes the journal
		// or reports its final metrics. Buffered results alone only avoid leaks.
		for range len(running) {
			result := <-results
			if result.err != nil && !passiveCancellationOnly(result.err) {
				resultErr = errors.Join(resultErr, result.err)
			}
		}
	}()
	var lastReport, lastSaturation time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		if queue == nil && len(signals) == 0 {
			return nil
		}
		var next string
		var due time.Time
		for id, at := range retries {
			if next == "" || at.Before(due) {
				next, due = id, at
			}
		}
		if next != "" && len(running) < maxConcurrent && !time.Now().Before(due) {
			delete(retries, next)
			running[next] = true
			go func(id string) {
				results <- passiveFinalizerResult{id: id, err: finalize(workCtx, id)}
			}(next)
			continue
		}
		var timer *time.Timer
		var retry <-chan time.Time
		if next != "" && len(running) < maxConcurrent {
			timer = time.NewTimer(max(time.Until(due), 0))
			retry = timer.C
		}
		input := queue
		if len(retries)+len(running) >= maxRetries {
			input = nil // Preserve every durable segment under retry saturation.
			if time.Since(lastSaturation) >= 30*time.Second {
				log.Printf("passive finalizer retry capacity reached: pending=%d limit=%d", len(retries)+len(running), maxRetries)
				lastSaturation = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case result := <-results:
			if timer != nil {
				timer.Stop()
			}
			delete(running, result.id)
			if result.err == nil {
				delete(signals, result.id)
				continue
			}
			if errors.Is(result.err, streamlog.ErrContentConflict) || errors.Is(result.err, streamlog.ErrQuarantined) || errors.Is(result.err, streamlog.ErrPassiveWALStopped) {
				return result.err
			}
			if time.Since(lastReport) >= 30*time.Second {
				log.Printf("passive stream segment %s finalization awaiting retry: %v", result.id, result.err)
				lastReport = time.Now()
			}
			retries[result.id] = time.Now().Add(retryDelay)
		case signal, ok := <-input:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				queue = nil
				if len(signals) != len(retries)+len(running) {
					return fmt.Errorf("passive finalizer closed with unfinished segments")
				}
				continue
			}
			id := signal.id
			var bit uint8
			switch signal.lane {
			case streamlog.Archive:
				bit = 1
			case streamlog.Search:
				bit = 2
			case streamlog.Projection:
				bit = 4
			default:
				return fmt.Errorf("invalid passive finalizer lane")
			}
			if id == "" {
				return fmt.Errorf("invalid passive finalizer segment")
			}
			if _, pending := retries[id]; pending || running[id] {
				continue
			}
			signals[id] |= bit
			if signals[id] == 7 {
				retries[id] = time.Now()
			}
		case <-retry:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}
