package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"proxy-sentinel/internal/devicesignal"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
)

func handshakeRouterPriority(ctx context.Context, scope *normalized.CaptureScope, interval time.Duration, read func(context.Context, string, string, string) (map[sharedaccess.OutletKey]struct{}, error)) func() devicesignal.RouterSamplingSnapshot {
	var current atomic.Pointer[devicesignal.RouterSamplingSnapshot]
	refresh := func() {
		query, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		keys, err := read(query, scope.SensorID, scope.CampusID, scope.AccessDomain)
		next := devicesignal.RouterSamplingSnapshot{Keys: keys}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			next = devicesignal.RouterSamplingSnapshot{LookupFailed: true}
			if prev := current.Load(); prev != nil && (!prev.LookupFailed || prev.ReusedPreviousList) {
				next.Keys = prev.Keys
				next.ReusedPreviousList = true
			}
			log.Printf("handshake authenticated router sampling lookup failed: %v", err)
		}
		current.Store(&next)
	}

	// Finish the bounded initial read before the capture socket opens, so an
	// entire bucket uses one immutable priority list, including its diagnostics.
	refresh()
	go func() {
		timer := time.NewTicker(interval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				refresh()
			}
		}
	}()
	return func() devicesignal.RouterSamplingSnapshot {
		next := current.Load()
		now := time.Now()
		if next == nil || now.Before(scope.ValidFrom) || !now.Before(scope.ValidUntil) {
			return devicesignal.RouterSamplingSnapshot{}
		}
		return *next
	}
}
