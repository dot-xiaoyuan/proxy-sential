package appdomain

import (
	"context"
	"sync"
	"time"
)

func (s *Service) databaseStep(ctx context.Context, lane string, now time.Time) (bool, error) {
	s.mu.RLock()
	enabled := s.config.Enabled
	s.mu.RUnlock()
	if !enabled || (s.historyDisabled && lane != "realtime") {
		return false, nil
	}
	b, _ := s.Library.Snapshot()
	more, err := s.backend.Step(ctx, lane, now, b)
	s.mu.Lock()
	if err != nil {
		s.lastError = err.Error()
	} else {
		s.lastError = ""
	}
	s.mu.Unlock()
	return more, err
}
func (s *Service) runDatabase(ctx context.Context) {
	var wg sync.WaitGroup
	// Exactly one realtime and one low-priority batch per process. The persisted
	// leases additionally prevent overlap across processes.
	for _, kind := range []string{"realtime", "background"} {
		wg.Add(1)
		go func(kind string) {
			defer wg.Done()
			delay := time.Duration(0)
			history := true
			for {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				lane := kind
				if kind == "background" {
					lane = "reconcile"
					if history {
						lane = "history"
					}
					history = !history
				}
				more, err := s.databaseStep(ctx, lane, time.Now().UTC())
				delay = time.Second
				if kind == "realtime" {
					if more {
						delay = 100 * time.Millisecond
					} else {
						delay = 2 * time.Second
					}
				} else {
					s.mu.RLock()
					ms := s.config.HistoryIntervalMS
					s.mu.RUnlock()
					if ms > 0 {
						delay = time.Duration(ms) * time.Millisecond
					}
				}
				if err != nil {
					delay = 30 * time.Second
				}
			}
		}(kind)
	}
	wg.Wait()
}
