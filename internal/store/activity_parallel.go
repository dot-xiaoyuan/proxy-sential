package store

import (
	"context"
	"sync"
)

// Bound independent chart queries rather than issuing a long serial chain.
// The first real failure cancels remaining work without leaking goroutines.
func runActivityQueries(parent context.Context, jobs []func(context.Context) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var first sync.Once
	var failure error
	for _, job := range jobs {
		wg.Add(1)
		go func(job func(context.Context) error) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slots }()
			if err := job(ctx); err != nil {
				first.Do(func() { failure = err; cancel() })
			}
		}(job)
	}
	wg.Wait()
	if failure != nil {
		return failure
	}
	return parent.Err()
}
