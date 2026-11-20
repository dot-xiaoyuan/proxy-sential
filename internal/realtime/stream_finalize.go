package realtime

import (
	"context"
	"errors"
	"time"

	"proxy-sentinel/internal/streamlog"
)

var errStreamFinalizationParked = errors.New("stream finalization parked until source recovery")

// A source's archive, search and projection lanes complete independently.
// Retry every unfinished finalization without letting one slow segment hold
// the later segments whose three acknowledgements are already durable.
func runStreamFinalizer(ctx context.Context, queue <-chan string, poll time.Duration, run func(context.Context, string) error, completed func(string), reportTransient func(error)) error {
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	type retry struct {
		id      string
		at      time.Time
		attempt int
	}
	pending := make([]retry, 0)
	for {
		if len(pending) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case id := <-queue:
				pending = append(pending, retry{id: id})
			}
		}
		for i := 0; i < len(pending); {
			if ctx.Err() != nil {
				return nil
			}
			if time.Now().Before(pending[i].at) {
				i++
				continue
			}
			id := pending[i].id
			err := run(ctx, id)
			if err == nil {
				completed(id)
				pending = append(pending[:i], pending[i+1:]...)
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, errStreamFinalizationParked) {
				// Retain the source permit and durable segment. This worker
				// can still finalize unrelated segments whose lanes ACKed.
				pending = append(pending[:i], pending[i+1:]...)
				continue
			}
			if streamPermanentError(err) {
				return err
			}
			if !errors.Is(err, streamlog.ErrUnconfirmed) {
				reportTransient(err)
			}
			pending[i].at = time.Now().Add(streamRetryDelay(poll, pending[i].attempt, err))
			if !errors.Is(err, streamlog.ErrUnconfirmed) {
				pending[i].attempt++
			}
			i++
		}
		select {
		case <-ctx.Done():
			return nil
		case id := <-queue:
			pending = append(pending, retry{id: id})
		case <-ticker.C:
		}
	}
}
