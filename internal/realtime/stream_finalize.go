package realtime

import (
	"context"
	"errors"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// A source's archive, search and projection lanes complete independently.
// Retry every unfinished finalization without letting one slow segment hold
// the later segments whose three acknowledgements are already durable.
func runStreamFinalizer(ctx context.Context, queue <-chan string, poll time.Duration, run func(context.Context, string) error, completed func(string), reportTransient func(error)) error {
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	pending := make([]string, 0)
	for {
		if len(pending) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case id := <-queue:
				pending = append(pending, id)
			}
		}
		for i := 0; i < len(pending); {
			if ctx.Err() != nil {
				return nil
			}
			id := pending[i]
			err := run(ctx, id)
			if err == nil {
				completed(id)
				pending = append(pending[:i], pending[i+1:]...)
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			if streamPermanentError(err) {
				return err
			}
			if !errors.Is(err, streamlog.ErrUnconfirmed) {
				reportTransient(err)
			}
			i++
		}
		select {
		case <-ctx.Done():
			return nil
		case id := <-queue:
			pending = append(pending, id)
		case <-ticker.C:
		}
	}
}
