package store

import (
	"context"
	"time"
)

type inventoryTimingKey struct{}

// WithDeviceInventoryTiming records only fixed stage names and durations, never identifiers.
func WithDeviceInventoryTiming(ctx context.Context, record func(string, time.Duration)) context.Context {
	return context.WithValue(ctx, inventoryTimingKey{}, record)
}
func inventoryTiming(ctx context.Context, stage string, start time.Time) {
	RecordDeviceInventoryTiming(ctx, stage, time.Since(start))
}

func RecordDeviceInventoryTiming(ctx context.Context, stage string, duration time.Duration) {
	if record, ok := ctx.Value(inventoryTimingKey{}).(func(string, time.Duration)); ok {
		record(stage, duration)
	}
}
