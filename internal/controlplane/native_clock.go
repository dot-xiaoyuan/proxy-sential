package controlplane

import (
	"context"
	"fmt"
	"time"
)

// Wait for small source clock skew; do not change or accept a future timestamp.
func waitNativeObservation(ctx context.Context, at time.Time) error {
	delay := time.Until(at)
	if delay <= 0 {
		return ctx.Err()
	}
	if delay > 250*time.Millisecond {
		return fmt.Errorf("authoritative source clock is ahead")
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
