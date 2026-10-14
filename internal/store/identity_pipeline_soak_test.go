package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"proxy-sentinel/internal/normalized"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestIdentityPipelineSoak(t *testing.T) {
	duration, err := time.ParseDuration(os.Getenv("PROXY_SENTINEL_IDENTITY_SOAK_DURATION"))
	if err != nil || duration <= 0 {
		t.Skip("explicit isolated soak duration required")
	}
	rate, _ := strconv.Atoi(os.Getenv("PROXY_SENTINEL_IDENTITY_SOAK_RATE"))
	if rate < 20 {
		rate = 20
	}
	pg := inboxTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := IdentityScope{Source: "soak", SensorID: fmt.Sprintf("soak-%d", time.Now().UnixNano()), CampusID: "campus", AccessDomain: "domain"}
	key := IdentityScopeKey(scope)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	// Field-scale snapshot: 35k current sessions, with 10k accounts and dual-stack
	// rows. The private build is outside the live authority transaction.
	snap := IdentitySnapshot{IdentityScope: scope, SnapshotID: "baseline", ObservedAt: at, IntervalSeconds: 1800}
	for i := 0; i < 35000; i++ {
		event := inboxEvent(scope, fmt.Sprintf("base-%d", i), fmt.Sprintf("session-%d", i), fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), "reconcile", at)
		event.Subject["account_id"] = fmt.Sprintf("account-%d", i%10000)
		snap.Events = append(snap.Events, event)
	}
	start := time.Now()
	if err = pg.calibrateIdentitySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	t.Logf("baseline 35000 sessions built in %s", time.Since(start))
	// Slow derived history cannot block acceptance/current identity. This lock is
	// held only in the isolated test database, never against the business database.
	history, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer history.Rollback()
	if _, err = history.ExecContext(ctx, `LOCK TABLE identity_ip_mac_history IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var txTimes, acceptTimes, getTimes, processingTimes []time.Duration
	workerErr := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			w, e := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
			if e == sql.ErrNoRows {
				select {
				case <-ctx.Done():
					return
				case <-time.After(20 * time.Millisecond):
				}
				continue
			}
			if e != nil {
				workerErr <- e
				return
			}
			begin := time.Now()
			work, stop := context.WithTimeout(ctx, 2*time.Second)
			e = pg.applyIdentityInbox(work, w)
			stop()
			elapsed := time.Since(begin)
			if e != nil {
				workerErr <- e
				return
			}
			mu.Lock()
			txTimes = append(txTimes, elapsed)
			mu.Unlock()
			var latency sql.NullFloat64
			if e = pg.db.QueryRowContext(ctx, `SELECT EXTRACT(epoch FROM completed_at-accepted_at) FROM identity_ingest_batches WHERE batch_id=$1`, w.BatchID).Scan(&latency); e != nil {
				workerErr <- e
				return
			}
			if latency.Valid {
				mu.Lock()
				processingTimes = append(processingTimes, time.Duration(latency.Float64*float64(time.Second)))
				mu.Unlock()
			}
		}
	}()
	produced := 0
	deadline := time.Now().Add(duration)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastReport := time.Now()
	for time.Now().Before(deadline) {
		events := make([]normalized.Event, rate)
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		for i := range events {
			n := produced + i
			sid := n % 35000
			status := "start"
			if (n/35000)%2 == 1 {
				status = "stop"
			}
			events[i] = inboxEvent(scope, fmt.Sprintf("%s-%d", key, n), fmt.Sprintf("session-%d", sid), fmt.Sprintf("10.%d.%d.%d", sid/65536, (sid/256)%256, sid%256), status, stamp)
			events[i].Subject["account_id"] = fmt.Sprintf("account-%d", sid%10000)
		}
		begin := time.Now()
		if _, err = pg.acceptIdentityBatch(ctx, fmt.Sprintf("%s-b%d", key, produced), fmt.Sprint(produced), scope, events, len(events)); err != nil {
			t.Fatal(err)
		}
		acceptTimes = append(acceptTimes, time.Since(begin))
		produced += rate
		begin = time.Now()
		summary, e := ReadIdentityPipelineSummary(ctx, pg.db, scope)
		getTimes = append(getTimes, time.Since(begin))
		if e != nil {
			t.Fatal(e)
		}
		if time.Since(lastReport) >= time.Minute {
			t.Logf("elapsed=%s input=%d pending=%d export_pending=%d", duration-time.Until(deadline), produced, summary.PendingRecords, summary.ExportPendingRecords)
			lastReport = time.Now()
		}
		if summary.PendingRecords > int64(rate*10) {
			t.Fatalf("backlog grows beyond 10s: %d", summary.PendingRecords)
		}
		select {
		case err = <-workerErr:
			t.Fatal(err)
		case <-ticker.C:
		}
	}
	drainDeadline := time.Now().Add(15 * time.Second)
	for {
		summary, e := ReadIdentityPipelineSummary(ctx, pg.db, scope)
		if e != nil {
			t.Fatal(e)
		}
		if summary.PendingRecords == 0 {
			break
		}
		if time.Now().After(drainDeadline) {
			t.Fatal("backlog did not drain")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	p95 := func(values []time.Duration) time.Duration {
		sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
		if len(values) == 0 {
			t.Fatal("missing latency sample")
		}
		return values[(len(values)-1)*95/100]
	}
	a, g, x, p := p95(acceptTimes), p95(getTimes), p95(txTimes), p95(processingTimes)
	t.Logf("SOAK PASSED duration=%s rate=%d records/s total=%d p95_accept=%s p95_status=%s p95_transaction=%s p95_processing=%s; history writes blocked and export held throughout", duration, rate, produced, a, g, x, p)
	if a > time.Second || g > 300*time.Millisecond || x > 2*time.Second || p > 5*time.Second {
		t.Fatal("latency SLO failed")
	}
}
