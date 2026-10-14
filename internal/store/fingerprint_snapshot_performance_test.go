package store

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"proxy-sentinel/internal/fingerprint"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// Opt-in destructive benchmark, restricted to the named disposable database.
// Clone the local 184 snapshot into sentinel_fp_benchmark before running it.
func TestFingerprintSnapshotPipelineReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_FINGERPRINT_BENCH_DSN")
	if dsn == "" {
		t.Skip("explicit disposable snapshot database required")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Path != "/sentinel_fp_benchmark" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		t.Fatal("benchmark restricted to local sentinel_fp_benchmark")
	}
	t.Setenv("PROXY_SENTINEL_DOMAIN_RECOGNITION_DISABLED", "true")
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn, SensorID: "ncu-184-router-pilot"})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	pg.db.SetMaxOpenConns(1)
	pg.db.SetMaxIdleConns(1)
	s := &DBStore{pg: pg}
	ctx := context.Background()
	if dir := os.Getenv("PROXY_SENTINEL_FINGERPRINT_BENCH_LIBRARY"); dir != "" {
		fingerprint.NewManager(dir)
	}
	original := fingerprint.Default()
	defer fingerprint.SetDefault(original)
	base := *original
	if err = base.LoadCatalog(nil); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.db.Exec(`CREATE TEMP TABLE bench_endpoints AS SELECT endpoint_id FROM endpoint_entities WHERE entity_role='endpoint' AND attributes ?| ARRAY['vendor_class','server','user_agent','requested_options'] ORDER BY endpoint_id LIMIT 1000`); err != nil {
		t.Fatal(err)
	}
	writes := func() int64 {
		if _, e := pg.db.Exec(`SELECT pg_stat_force_next_flush()`); e != nil {
			t.Fatal(e)
		}
		if _, e := pg.db.Exec(`SELECT pg_stat_clear_snapshot()`); e != nil {
			t.Fatal(e)
		}
		var n int64
		if e := pg.db.QueryRow(`SELECT COALESCE(sum(n_tup_ins+n_tup_upd+n_tup_del),0) FROM pg_stat_user_tables WHERE relname IN ('endpoint_recognition_jobs','endpoint_recognition_summary')`).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	reports := []map[string]any{}
	for round := 0; round < 3; round++ {
		variants := []struct {
			name string
			lib  *fingerprint.Library
		}{{"baseline_without_catalog", &base}, {"expanded_catalog", original}}
		if round%2 == 1 {
			variants[0], variants[1] = variants[1], variants[0]
		}
		for _, v := range variants {
			fingerprint.SetDefault(v.lib)
			if _, err = pg.db.Exec(`TRUNCATE endpoint_recognition_jobs; INSERT INTO endpoint_recognition_jobs(endpoint_id) SELECT endpoint_id FROM bench_endpoints`); err != nil {
				t.Fatal(err)
			}
			startWrites := writes()
			var statsBefore int64
			if err = pg.db.QueryRow(`SELECT COALESCE(sum(n_tup_ins+n_tup_upd+n_tup_del),0) FROM pg_stat_user_tables WHERE relname='read_model_runtime_state'`).Scan(&statsBefore); err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			waits := []float64{}
			count := 0
			for {
				job, found, e := s.claimRecognitionJob(ctx, "benchmark-0")
				if e != nil {
					t.Fatal(e)
				}
				if !found {
					break
				}
				waits = append(waits, float64(time.Since(started).Microseconds())/1000)
				if e = s.materializeRecognition(ctx, job); e != nil {
					t.Fatal("materialize", e)
				}
				if e = s.finishRecognitionJob(ctx, job, nil); e != nil {
					t.Fatal(e)
				}
				count++
			}
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			flushStart := time.Now()
			if err = s.flushFingerprintMatchCounts(ctx); err != nil {
				t.Fatal(err)
			}
			flushMillis := float64(time.Since(flushStart).Microseconds()) / 1000
			endWrites := writes()
			var statsAfter int64
			if err = pg.db.QueryRow(`SELECT COALESCE(sum(n_tup_ins+n_tup_upd+n_tup_del),0) FROM pg_stat_user_tables WHERE relname='read_model_runtime_state'`).Scan(&statsAfter); err != nil {
				t.Fatal(err)
			}
			sort.Float64s(waits)
			if count == 0 {
				t.Fatal("empty snapshot")
			}
			reports = append(reports, map[string]any{"statistics_rows_written": statsAfter - statsBefore, "statistics_flush_ms": flushMillis, "round": round + 1, "variant": v.name, "endpoints": count, "elapsed_ms": float64(elapsed.Microseconds()) / 1000, "endpoints_per_second": float64(count) / elapsed.Seconds(), "batch_queue_wait_p50_ms": waits[len(waits)/2], "batch_queue_wait_p95_ms": waits[len(waits)*95/100], "database_rows_written": endWrites - startWrites, "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "heap_inuse_bytes": after.HeapInuse})
		}
	}
	data, _ := json.MarshalIndent(map[string]any{"scope": "same isolated 184 snapshot, same 1000 endpoint batch, one real recognition worker, three alternating rounds; no ingest or active scan", "results": reports}, "", "  ")
	output := os.Getenv("PROXY_SENTINEL_FINGERPRINT_BENCH_REPORT")
	if output != "" && !strings.Contains(output, "..") {
		if err = os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Log(string(data))
	}
}
