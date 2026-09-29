package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"proxy-sentinel/internal/appdomain"
)

// Explicit opt-in: this benchmark writes only to the supplied isolated test DB.
// It exercises CH source scans, matching, PG batch commits and CH result queries.
func TestApplicationDatabaseEndToEndCapacity(t *testing.T) {
	count, _ := strconv.Atoi(os.Getenv("PROXY_SENTINEL_APP_CAPACITY"))
	if count != 100000 && count != 1000000 {
		t.Skip("set PROXY_SENTINEL_APP_CAPACITY to 100000 or 1000000")
	}
	d := appIntegrationDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sensor := fmt.Sprintf("app-capacity-%d", now.UnixNano())
	var existing int
	if err := d.store.pg.db.QueryRowContext(ctx, "SELECT count(*) FROM application_processing_jobs").Scan(&existing); err != nil {
		t.Fatal(err)
	}
	if existing != 0 {
		t.Fatal("capacity tests require an isolated task database")
	}
	t.Cleanup(func() {
		_, _ = d.store.pg.db.ExecContext(ctx, "DELETE FROM application_processing_batches")
		_, _ = d.store.pg.db.ExecContext(ctx, "DELETE FROM application_processing_jobs")
		_ = d.store.ch.exec(ctx, "ALTER TABLE normalized_events DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2")
		cleanupApplicationTestData(ctx, d.store, sensor, false)
	})
	seed := fmt.Sprintf(`INSERT INTO normalized_events(timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,observer_json,payload_json,flow_json,raw_ref_json) SELECT toDateTime64(now()-INTERVAL 1 HOUR,6)+toIntervalMicrosecond(number),concat('capacity-',toString(number)),'v1','test','tls','tls',%s,concat('10.0.',toString(intDiv(number%%1000,250)),'.',toString(number%%250+1)),'{}','{"sni":"weixin.qq.com"}',concat('{"connection_id":"c',toString(intDiv(number,10)),'","bytes_toserver":',toString(number%%10+1),',"bytes_toclient":20}'),'{}' FROM numbers(%d)`, chQuote(sensor), count)
	if err := d.store.ch.exec(ctx, seed); err != nil {
		t.Fatal(err)
	}
	raw, err := appdomain.ExampleBundle(now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := appdomain.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Start(ctx, now, b.Manifest.Version); err != nil {
		t.Fatal(err)
	}
	// Realtime is already caught up to the benchmark's initial wall clock.
	rt := appdomain.Job{ID: appToken(), Status: "completed", To: now, Version: b.Manifest.Version}
	jr, _ := json.Marshal(rt)
	if _, err = d.store.pg.db.ExecContext(ctx, "INSERT INTO application_processing_jobs(lane,job) VALUES('realtime',$1)", jr); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	peak := uint64(0)
	rtDelay := time.Duration(0)
	var midHeap uint64
	for batch := 0; ; batch++ {
		more, e := d.Step(ctx, "history", now, b)
		if e != nil {
			t.Fatal(e)
		}
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		peak = max(peak, mem.HeapAlloc)
		progress, stateErr := d.State(ctx)
		if stateErr != nil {
			t.Fatal(stateErr)
		}
		if midHeap == 0 && progress.History.Processed >= count/2 {
			runtime.GC()
			runtime.ReadMemStats(&mem)
			midHeap = mem.HeapAlloc
			insert := fmt.Sprintf(`INSERT INTO normalized_events(timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,observer_json,payload_json,flow_json,raw_ref_json) VALUES(now64(6),'realtime-probe','v1','test','tls','tls',%s,'10.1.1.1','{}','{"sni":"weixin.qq.com"}','{"connection_id":"probe"}','{}')`, chQuote(sensor))
			if e = d.store.ch.exec(ctx, insert); e != nil {
				t.Fatal(e)
			}
			rtStart := time.Now()
			if _, e = d.Step(ctx, "realtime", time.Now().UTC(), b); e != nil {
				t.Fatal(e)
			}
			rtDelay = time.Since(rtStart)
			st, e := d.State(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if st.Realtime.Processed != 1 {
				t.Fatalf("realtime failed to catch fresh event during history: %+v", st.Realtime)
			}
		}
		if batch%100 == 0 {
			t.Logf("capacity=%d batches=%d elapsed=%s heap=%d", count, batch, time.Since(started).Round(time.Millisecond), mem.HeapAlloc)
		}
		if !more {
			break
		}
	}
	elapsed := time.Since(started)
	queryAt := time.Now()
	q := appdomain.Query{From: now.Add(-2 * time.Hour), To: time.Now().UTC(), SensorID: sensor}
	report, err := d.Report(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	queryElapsed := time.Since(queryAt)
	if report.ObservationCount != count+1 {
		t.Fatalf("count mismatch %d", report.ObservationCount)
	}
	if len(report.Items) != 1 || report.Items[0].ConnectionCount != count/10+1 {
		t.Fatalf("connection mismatch %+v", report.Items)
	}
	runtime.GC()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	if mem.HeapAlloc > 128<<20 {
		t.Fatalf("unexpected retained Go heap: %d", mem.HeapAlloc)
	}
	result := map[string]any{"events": count, "processing_seconds": elapsed.Seconds(), "events_per_second": float64(count) / elapsed.Seconds(), "peak_go_heap_bytes": peak, "midpoint_live_heap_bytes": midHeap, "final_live_heap_bytes": mem.HeapAlloc, "query_millis": queryElapsed.Milliseconds(), "realtime_probe_millis": rtDelay.Milliseconds(), "batch_size": 1000, "note": "manual batch stepping excludes configured background sleep; CPU/memory and DB metrics are local test results"}
	encoded, _ := json.Marshal(result)
	t.Logf("CAPACITY_RESULT %s", encoded)
}
