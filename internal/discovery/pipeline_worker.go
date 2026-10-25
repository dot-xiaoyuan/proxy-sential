package discovery

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

// Each lane owns a bounded resource budget. Background errors never stop the
// realtime pumps, and every durable task keeps its retry/confirmation history.
func (r Repository) RunProjectionWorkers(ctx context.Context, spool, sensor string, config CollectionConfig, masterKey []byte) error {
	options, _ := NewWorkerOptions("all", 2)
	return r.RunProjectionWorkersConfigured(ctx, spool, sensor, config, masterKey, options)
}
func (r Repository) RunProjectionWorkersConfigured(ctx context.Context, spool, sensor string, config CollectionConfig, masterKey []byte, options WorkerOptions) error {
	if _, err := NewWorkerOptions(options.Mode, options.RealtimeWorkers); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var blocked bool
	if err := r.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_batch_work WHERE lane IN ('realtime','backfill') AND NOT completed AND error='content_conflict')`).Scan(&blocked); err != nil {
		return err
	}
	if blocked {
		return ErrDiscoveryContentConflict
	}
	if options.Capture() {
		if e := r.ConfigureProtocolRuntime(ctx, sensor, config); e != nil {
			return e
		}
	}
	realtime, backfill := newPipelineObserver(), newPipelineObserver()
	background := r
	if r.BackfillArchive != nil {
		background.Archive = r.BackfillArchive
	}
	if r.BackfillDB != nil {
		background.DB = r.BackfillDB
	}
	monitor := r
	if r.RuntimeDB != nil {
		monitor.DB = r.RuntimeDB
	}
	fatal := make(chan error, 1)
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
					job, jobCancel := context.WithTimeout(ctx, budget)
					e := work(job)
					jobCancel()
					if e != nil && ctx.Err() == nil {
						log.Print("discovery background task: ", WorkErrorCode(e))
						if errors.Is(e, ErrDiscoveryContentConflict) {
							select {
							case fatal <- e:
							default:
							}
							cancel()
						}
					}
				}
			}
		}()
	}
	for i := 0; i < options.RealtimeWorkers; i++ {
		start(50*time.Millisecond, 4*time.Second, func(c context.Context) error {
			_, e := r.ProcessDiscoveryBatch(WithPipelineObserver(c, realtime))
			return e
		})
	}
	start(250*time.Millisecond, time.Second, r.ExpireDiscoveryStates)
	start(time.Second, time.Second, background.UpdateDiscoveryStatistics)
	start(time.Hour, 2*time.Second, background.CleanupDiscoveryHotHistory)
	if options.Capture() {
		start(time.Second, time.Second, func(c context.Context) error { return background.UpdateCaptureRuntime(c, spool, sensor) })
		start(5*time.Second, 2*time.Second, func(c context.Context) error {
			e := r.WriteZeekCandidateProfileConfigured(c, spool, sensor, config)
			report := r.SetMetadataProfileStatus(c, sensor, e)
			if e != nil {
				return e
			}
			return report
		})
	}
	start(2*time.Second, 3*time.Second, func(c context.Context) error {
		// Backfill has its own pool and worker. Only overdue realtime work pauses
		// new claims; mere presence of realtime traffic no longer starves recovery.
		var overdue bool
		if e := monitor.DB.QueryRowContext(c, `SELECT EXISTS(SELECT 1 FROM discovery_batch_work WHERE lane='realtime' AND NOT completed AND created_at<now()-interval '5 seconds')`).Scan(&overdue); e != nil {
			return e
		}
		if overdue {
			backfill.SetPause("realtime_overdue")
			return nil
		}
		backfill.SetPause("")
		c = WithPipelineObserver(c, backfill)
		worked, e := background.ProcessDiscoveryLane(c, "backfill")
		if e != nil || worked {
			return e
		}
		if !options.GenerateBackfill() {
			return nil
		}
		_, e = background.BackfillDiscoveryPage(c)
		return e
	})
	flush := func(c context.Context) error {
		if e := realtime.flush(c, monitor.DB, sensor+"/realtime", "realtime", options.Mode); e != nil {
			return e
		}
		if e := backfill.flush(c, monitor.DB, sensor+"/backfill", "backfill", options.Mode); e != nil {
			return e
		}
		return monitor.RefreshPipelineSummary(c)
	}
	initial, initialCancel := context.WithTimeout(ctx, 2*time.Second)
	if err := flush(initial); err != nil {
		initialCancel()
		cancel()
		wg.Wait()
		return err
	}
	initialCancel()
	start(5*time.Second, 2*time.Second, flush)
	if !options.Active() {
		wg.Wait()
		select {
		case err := <-fatal:
			return err
		default:
			return ctx.Err()
		}
	}
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
						log.Print("discovery enrichment task: ", WorkErrorCode(e))
					}
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-fatal:
		return err
	default:
		return ctx.Err()
	}
}
