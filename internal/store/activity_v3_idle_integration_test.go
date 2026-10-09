package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"proxy-sentinel/internal/normalized"
)

func activityV3PrivatePostgres(t *testing.T) *DBStore {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	schema := fmt.Sprintf("activity_idle_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { db.Close(); admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	raw, err := os.ReadFile("../../migrations/postgres/060_single_node_high_load_v3.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(strings.Split(string(raw), "CREATE TABLE IF NOT EXISTS endpoint_recognition_summary")[0]); err != nil {
		t.Fatal(err)
	}
	return &DBStore{pg: &PostgresStore{db: db}}
}

func TestActivityV3VerifiedIdleDoesNotStarveCoarsePostgres(t *testing.T) {
	s := activityV3PrivatePostgres(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	t.Setenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3", "true")
	if _, err := s.pg.db.Exec(`INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES
 ('activity-v3-5m',jsonb_build_object('as_of',$1::text),$1::timestamptz),
 ('activity-v3-realtime-health','{"status":"ready","last_error":""}', $2)`, now.Add(-2*time.Hour).Format(time.RFC3339Nano), now); err != nil {
		t.Fatal(err)
	}
	lag, err := s.activityV3RealtimeLag(ctx, now)
	if err != nil || lag != 0 {
		t.Fatalf("healthy quiet worker starves hour/day aggregation: lag=%v err=%v", lag, err)
	}
	if err = s.StatisticsReadModelHealth(ctx); err != nil {
		t.Fatalf("healthy idle statistics shown as delayed: %v", err)
	}
	// No source data timestamp is fabricated to make the worker appear healthy.
	var asOf time.Time
	if err = s.pg.db.QueryRow(`SELECT (state->>'as_of')::timestamptz FROM read_model_runtime_state WHERE name='activity-v3-5m'`).Scan(&asOf); err != nil || !asOf.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("idle health changed event coverage: %s err=%v", asOf, err)
	}
	// A quiet live bucket may await its future finalization deadline, while prior
	// closed hours can proceed. It becomes actionable exactly at the deadline.
	bucket := now.Truncate(5 * time.Minute)
	deadline := bucket.Add(5*time.Minute + 90*time.Second)
	if _, err = s.pg.db.Exec(`INSERT INTO read_model_jobs(model,bucket_start,sensor_id,not_before,dirty_generation,processed_generation) VALUES('activity-5m-v3',$1,'quiet',$2,2,1)`, bucket, deadline); err != nil {
		t.Fatal(err)
	}
	if lag, err = s.activityV3RealtimeLag(ctx, now); err != nil || lag != 0 {
		t.Fatalf("future finalization incorrectly blocks previous hours: %v %v", lag, err)
	}
	if _, err = s.pg.db.Exec(`UPDATE read_model_runtime_state SET updated_at=$1 WHERE name='activity-v3-realtime-health'`, deadline); err != nil {
		t.Fatal(err)
	}
	if lag, err = s.activityV3RealtimeLag(ctx, deadline); err != nil || lag < 90 {
		t.Fatalf("unfinalized closed bucket bypassed lag guard: %v %v", lag, err)
	}
	// Even a retry with a future not_before must not hide unfinished old work.
	if _, err = s.pg.db.Exec(`UPDATE read_model_jobs SET not_before=$1,attempts=1 WHERE sensor_id='quiet'`, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if lag, err = s.activityV3RealtimeLag(ctx, deadline); err != nil || lag < 90 {
		t.Fatalf("retry backoff hid old backlog: %v %v", lag, err)
	}
	if _, err = s.pg.db.Exec(`DELETE FROM read_model_jobs`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(`UPDATE read_model_runtime_state SET updated_at=$1 WHERE name='activity-v3-realtime-health'`, now.Add(-31*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.activityV3RealtimeLag(ctx, now); err == nil {
		t.Fatal("stopped worker appeared healthy")
	}
	if _, err = s.pg.db.Exec(`UPDATE read_model_runtime_state SET updated_at=$1,state='{"status":"failed","last_error":"receipt query unavailable"}' WHERE name='activity-v3-realtime-health'`, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.activityV3RealtimeLag(ctx, now); err == nil {
		t.Fatal("failed dispatcher appeared healthy")
	}
}

func TestActivityV3RealtimeCheckpointPreservesLastSuccessPostgres(t *testing.T) {
	s := activityV3PrivatePostgres(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.recordActivityV3RealtimeHealth(ctx, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := s.recordActivityV3RealtimeHealth(ctx, errors.New("source receipt query failed"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var status, lastError, lastSuccess string
	if err := s.pg.db.QueryRow(`SELECT state->>'status',state->>'last_error',state->>'last_success_at' FROM read_model_runtime_state WHERE name='activity-v3-realtime-health'`).Scan(&status, &lastError, &lastSuccess); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || lastError != "source receipt query failed" || lastSuccess != now.Format(time.RFC3339Nano) {
		t.Fatalf("failure overwrote success history: %s %s %s", status, lastError, lastSuccess)
	}
	if err := s.recordActivityV3RealtimeHealth(ctx, nil, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.pg.db.QueryRow(`SELECT state->>'status',state->>'last_error',state->>'last_success_at' FROM read_model_runtime_state WHERE name='activity-v3-realtime-health'`).Scan(&status, &lastError, &lastSuccess); err != nil {
		t.Fatal(err)
	}
	if status != "ready" || lastError != "" || lastSuccess != now.Add(2*time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("recovery failed: %s %s %s", status, lastError, lastSuccess)
	}
}

func TestActivityV3QuietWorkerPublishesAndRemainsHealthy(t *testing.T) {
	d := appIntegrationDB(t)
	s := activityV3PrivatePostgres(t)
	s.ch = d.store.ch
	ctx := context.Background()
	now := time.Now().UTC()
	bucket := now.Truncate(time.Hour).Add(-2 * time.Hour)
	sensor := fmt.Sprintf("quiet-worker-%d", now.UnixNano())
	t.Setenv("PROXY_SENTINEL_ACTIVITY_V3_CUTOVER", bucket.Add(-time.Hour).Format(time.RFC3339Nano))
	if _, err := s.ensureActivityV3Cutover(ctx); err != nil {
		t.Fatal(err)
	}
	event := normalized.Event{EventID: sensor, SchemaVersion: "1", Source: "test", Type: "dns", Timestamp: bucket.Add(time.Minute).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor}, Subject: map[string]any{"ip": "192.0.2.17"}, Payload: map[string]any{"query": "quiet-worker.example"}}
	if err := s.ch.WriteNormalizedEvents(ctx, []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	// The packet was already dispatched before the device fell quiet. Resume
	// that durable queue without another receipt, packet or fake event timestamp.
	raw, err := s.ch.query(ctx, `SELECT concat(replaceOne(toString(written_at),' ','T'),'Z') written_at,formatDateTime(window_start,'%Y-%m-%dT%H:%i:%SZ','UTC') window_start,sensor_id,campus_id FROM activity_chart_dirty_log ORDER BY written_at DESC,window_start DESC,sensor_id DESC,campus_id DESC LIMIT 1 FORMAT JSONEachRow`)
	if err != nil {
		t.Fatal(err)
	}
	cursors := []activityChartCursor{}
	if err = decodeJSONEachRow(raw, &cursors); err != nil || len(cursors) != 1 {
		t.Fatalf("missing dispatch fixture cursor: %v %+v", err, cursors)
	}
	cursor, err := json.Marshal(cursors[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(`INSERT INTO read_model_runtime_state(name,state) VALUES('activity-v3-dispatch',$1)`, cursor); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pg.db.Exec(`INSERT INTO read_model_jobs(model,bucket_start,sensor_id) VALUES('activity-5m-v3',$1,$2)`, bucket, sensor); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.RunActivityV3Realtime(workerCtx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("realtime worker did not stop")
		}
	}()
	limit := time.Now().Add(30 * time.Second)
	completed := false
	for time.Now().Before(limit) {
		if err = s.pg.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM read_model_jobs WHERE model='activity-5m-v3' AND sensor_id=$1 AND status='completed') AND EXISTS(SELECT 1 FROM read_model_runtime_state WHERE name='activity-v3-realtime-health' AND state->>'status'='ready')`, sensor).Scan(&completed); err != nil {
			t.Fatal(err)
		}
		if completed {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !completed {
		t.Fatal("quiet worker failed to finish its queued bucket")
	}
	var parents int
	if err = s.pg.db.QueryRow(`SELECT count(*) FROM read_model_jobs WHERE model='activity-hour-v3' AND sensor_id=$1`, sensor).Scan(&parents); err != nil || parents != 1 {
		t.Fatalf("quiet worker lost its parent: %d %v", parents, err)
	}
	if lag, err := s.activityV3RealtimeLag(ctx, time.Now().UTC()); err != nil || lag != 0 {
		t.Fatalf("real quiet worker blocks coarser work: %v %v", lag, err)
	}
	raw, err = s.ch.query(ctx, `SELECT sum(event_count) count FROM activity_chart_facts_5m_v3 WHERE sensor_id=`+chQuote(sensor)+` AND dimension='type' AND revision=(SELECT argMax(revision,published_at) FROM activity_chart_bucket_versions_v3 WHERE granularity='5m' AND sensor_id=`+chQuote(sensor)+`) FORMAT JSONEachRow`)
	if err != nil {
		t.Fatal(err)
	}
	count, err := decodeSingleCount(raw)
	if err != nil || count != 1 {
		t.Fatalf("worker lost or duplicated source event: %d %v", count, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker failed to stop")
	}
	if _, err = s.activityV3RealtimeLag(ctx, time.Now().UTC().Add(31*time.Second)); err == nil {
		t.Fatal("stopped real worker bypassed freshness guard")
	}
}
