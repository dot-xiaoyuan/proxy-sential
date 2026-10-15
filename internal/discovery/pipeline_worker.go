package discovery

import (
	"context"
	"log"
	"sync"
	"time"
)

// Each lane owns a bounded resource budget. Background errors never stop the
// realtime pumps, and every durable task keeps its retry/confirmation history.
func (r Repository) RunProjectionWorkers(ctx context.Context, spool, sensor string, config CollectionConfig, masterKey []byte) error {
	if e := r.ConfigureProtocolRuntime(ctx, sensor, config); e != nil {
		return e
	}
	var wg sync.WaitGroup
	start := func(interval, budget time.Duration, work func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tick := time.NewTicker(interval)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					job, cancel := context.WithTimeout(ctx, budget)
					e := work(job)
					cancel()
					if e != nil && ctx.Err() == nil {
						log.Print("discovery background task: ", e)
					}
				}
			}
		}()
	}
	for i := 0; i < 2; i++ {
		start(50*time.Millisecond, 4*time.Second, func(c context.Context) error { _, e := r.ProcessDiscoveryBatch(c); return e })
	}
	start(250*time.Millisecond, time.Second, r.ExpireDiscoveryStates)
	start(time.Second, time.Second, r.UpdateDiscoveryStatistics)
	start(time.Hour, 2*time.Second, r.CleanupDiscoveryHotHistory)
	start(time.Second, time.Second, func(c context.Context) error { return r.UpdateCaptureRuntime(c, spool, sensor) })
	start(5*time.Second, 2*time.Second, func(c context.Context) error {
		e := r.WriteZeekCandidateProfileConfigured(c, spool, sensor, config)
		report := r.SetMetadataProfileStatus(c, sensor, e)
		if e != nil {
			return e
		}
		return report
	})
	start(2*time.Second, 3*time.Second, func(c context.Context) error {
		var pending bool
		if e := r.DB.QueryRowContext(c, `SELECT EXISTS(SELECT 1 FROM discovery_batch_work WHERE lane='realtime' AND NOT completed AND next_attempt_at<=now())`).Scan(&pending); e != nil {
			return e
		}
		if pending {
			return nil
		}
		worked, e := r.ProcessDiscoveryLane(c, "backfill")
		if e != nil || worked {
			return e
		}
		_, e = r.BackfillDiscoveryPage(c)
		return e
	})
	// Four independent jobs share a global start rate of two requests/second.
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := EnrichmentWorker{Repository: r, Paths: config.EnrichmentPaths, MasterKey: masterKey}
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					job, cancel := context.WithTimeout(ctx, 4*time.Second)
					_, e := w.Step(job)
					cancel()
					if e != nil && ctx.Err() == nil {
						log.Print("discovery enrichment task: ", e)
					}
				}
			}
		}()
	}
	wg.Wait()
	return ctx.Err()
}
