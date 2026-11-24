package main

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/sharedaccess"
)

func handshakeRouterPriority(ctx context.Context, scope *normalized.CaptureScope, read func(context.Context, string, string, string) (map[sharedaccess.OutletKey]struct{}, error)) func() map[sharedaccess.OutletKey]struct{} {
	var current atomic.Pointer[map[sharedaccess.OutletKey]struct{}]
	go func() {
		timer := time.NewTicker(30 * time.Second)
		defer timer.Stop()
		for {
			query, cancel := context.WithTimeout(ctx, 2*time.Second)
			keys, err := read(query, scope.SensorID, scope.CampusID, scope.AccessDomain)
			cancel()
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				current.Store(nil)
				log.Printf("handshake authenticated router sampling lookup failed: %v", err)
			} else {
				current.Store(&keys)
			}
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
	return func() map[sharedaccess.OutletKey]struct{} {
		keys := current.Load()
		now := time.Now()
		if keys == nil || now.Before(scope.ValidFrom) || !now.Before(scope.ValidUntil) {
			return nil
		}
		return *keys
	}
}
