package main

import (
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

func runQueueSampler(ctx context.Context, cfg config, password, token string, state *runtimeState) {
	client := redis.NewClient(&redis.Options{Addr: cfg.eventAddr, Password: password, ReadTimeout: time.Second, WriteTimeout: time.Second})
	defer func() { client.Close() }()
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		state.mu.RLock()
		address, list, processing, dead := state.activeEventAddr, state.activeEventList, state.activeProcessingList, state.activeDeadList
		state.mu.RUnlock()
		if address != "" && address != cfg.eventAddr {
			client.Close()
			cfg.eventAddr = address
			client = redis.NewClient(&redis.Options{Addr: address, Password: password, ReadTimeout: time.Second, WriteTimeout: time.Second})
		}
		if list != "" {
			cfg.eventList, cfg.processingList, cfg.deadList = list, processing, dead
		}

		updateQueueMetrics(work, client, cfg, state)
		cancel()
		if !waitContext(ctx, 5*time.Second) {
			return
		}
	}
}
