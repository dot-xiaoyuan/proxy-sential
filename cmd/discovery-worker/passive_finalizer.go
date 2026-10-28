package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"proxy-sentinel/internal/streamlog"
)

// A segment is finalized after all three lane notifications. A transient
// confirmation failure remains on a bounded retry schedule so other segments
// can progress; the journal remains the durable recovery source on restart.
type passiveFinalizerSignal struct {
	id   string
	lane streamlog.Lane
}

func runPassiveFinalizer(ctx context.Context, queue <-chan passiveFinalizerSignal, finalize func(context.Context, string) error, retryDelay time.Duration, maxRetries int) error {
	if retryDelay <= 0 || maxRetries <= 0 {
		return errors.New("invalid passive finalizer retry budget")
	}
	signals := map[string]uint8{}
	retries := map[string]time.Time{}
	var lastReport time.Time
	var lastSaturation time.Time
	attempt := func(id string) error {
		err := finalize(ctx, id)
		if err == nil {
			delete(signals, id)
			delete(retries, id)
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, streamlog.ErrContentConflict) || errors.Is(err, streamlog.ErrQuarantined) {
			return err
		}
		if time.Since(lastReport) >= 30*time.Second {
			log.Printf("passive stream segment %s finalization awaiting retry: %v", id, err)
			lastReport = time.Now()
		}
		retries[id] = time.Now().Add(retryDelay)
		return nil
	}
	for {
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
		var timer *time.Timer
		var retry <-chan time.Time
		if next != "" {
			timer = time.NewTimer(max(time.Until(due), 0))
			retry = timer.C
		}
		input := queue
		if len(retries) >= maxRetries {
			input = nil // Preserve every durable segment under retry saturation.
			if time.Since(lastSaturation) >= 30*time.Second {
				log.Printf("passive finalizer retry capacity reached: pending=%d limit=%d", len(retries), maxRetries)
				lastSaturation = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case signal, ok := <-input:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				queue = nil
				if len(signals) != len(retries) {
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
			if _, pending := retries[id]; pending {
				continue
			}
			signals[id] |= bit
			if signals[id] == 7 {
				if err := attempt(id); err != nil {
					return err
				}
			}
		case <-retry:
			if timer != nil {
				timer.Stop()
			}
			if err := attempt(next); err != nil {
				return err
			}
		}
	}
}
