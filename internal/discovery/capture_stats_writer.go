package discovery

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Shutdown can race with either writer. Preserve every non-cancellation
// failure, including capture overflow, while normalizing a clean shutdown to
// context.Canceled. Callers must compare that sentinel directly: a callback
// can return a joined error containing both cancellation and a real failure.
func joinCaptureErrors(errs ...error) error {
	var failures []error
	cancelled := false
	for _, err := range errs {
		if err == nil {
			continue
		}
		if captureCancellationOnly(err) {
			cancelled = true
			continue
		}
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if cancelled {
		return context.Canceled
	}
	return nil
}

func captureCancellationOnly(err error) bool {
	if err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !captureCancellationOnly(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return captureCancellationOnly(wrapped.Unwrap())
	}
	return false
}

// captureStatsWriter keeps at most one pending cumulative snapshot and one
// in-flight write. Only obsolete statistics are replaced: event batches and
// their durability path never pass through this writer. The capture goroutine
// owns the live stats and calls submit before it mutates them again.
type captureStatsWriter struct {
	mu       sync.Mutex
	pending  *CaptureStats
	closed   bool
	writeErr error
	wake     chan struct{}
	done     chan struct{}
}

func newCaptureStatsWriter(persist func(*CaptureStats) error) *captureStatsWriter {
	w := &captureStatsWriter{wake: make(chan struct{}, 1), done: make(chan struct{})}
	go w.run(persist)
	return w
}

func (s *CaptureStats) snapshot() *CaptureStats {
	snapshot := *s
	snapshot.UpdatedAt = time.Now().UTC()
	snapshot.Protocols = make(map[string]*ProtocolCaptureStats, len(s.Protocols))
	for key, value := range s.Protocols {
		if value != nil {
			copy := *value
			snapshot.Protocols[key] = &copy
		} else {
			snapshot.Protocols[key] = nil
		}
	}
	snapshot.Config.Protocols = append([]ProtocolOwner(nil), s.Config.Protocols...)
	snapshot.Config.EventBindings = append([]EventBinding(nil), s.Config.EventBindings...)
	snapshot.Config.EnrichmentPaths = append([]EnrichmentPath(nil), s.Config.EnrichmentPaths...)
	return &snapshot
}

func (w *captureStatsWriter) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *captureStatsWriter) submit(stats *CaptureStats) error {
	snapshot := stats.snapshot()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	if w.closed {
		return errors.New("capture statistics writer is closed")
	}
	w.pending = snapshot
	w.signal()
	return nil
}

func (w *captureStatsWriter) err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeErr
}

// close drains the latest submitted snapshot and joins the single writer.
// Filesystem errors remain visible to both the live capture loop and shutdown.
func (w *captureStatsWriter) close() error {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	w.signal()
	<-w.done
	return w.err()
}

func (w *captureStatsWriter) run(persist func(*CaptureStats) error) {
	defer close(w.done)
	for range w.wake {
		for {
			w.mu.Lock()
			snapshot, closed := w.pending, w.closed
			w.pending = nil
			w.mu.Unlock()
			if snapshot == nil {
				if closed {
					return
				}
				break
			}
			if err := persist(snapshot); err != nil {
				w.mu.Lock()
				w.writeErr = err
				w.pending = nil
				w.mu.Unlock()
				return
			}
		}
	}
}
