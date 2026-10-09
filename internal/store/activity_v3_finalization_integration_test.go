package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"proxy-sentinel/internal/normalized"
)

func TestActivityV3FinalizationRepairBoundedPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := fmt.Sprintf("activity_repair_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	raw, err := os.ReadFile("../../migrations/postgres/060_single_node_high_load_v3.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(strings.Split(string(raw), "CREATE TABLE IF NOT EXISTS endpoint_recognition_summary")[0]); err != nil {
		t.Fatal(err)
	}
	s := &DBStore{pg: &PostgresStore{db: db}}
	ctx := context.Background()
	if _, err = db.Exec(`INSERT INTO read_model_jobs(model,bucket_start,sensor_id,status,dirty_generation,processed_generation)
 SELECT 'activity-5m-v3',now()-interval '2 hours','legacy-'||n,'completed',3,3 FROM generate_series(1,101)n;
 INSERT INTO read_model_jobs(model,bucket_start,sensor_id,status,dirty_generation,processed_generation)
 VALUES('activity-5m-v3',now(),'live','completed',2,2),('activity-5m-v3',now()-interval '3 hours','busy','running',5,3);`); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{100, 1, 0} {
		got, err := s.repairActivityV3Finalization(ctx)
		if err != nil || got != want {
			t.Fatalf("repair pass %d got=%d want=%d err=%v", i, got, want, err)
		}
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM read_model_jobs WHERE sensor_id LIKE 'legacy-%' AND status='pending' AND dirty_generation=4 AND processed_generation=3`).Scan(&count); err != nil || count != 101 {
		t.Fatalf("lost repair generations count=%d err=%v", count, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM read_model_jobs WHERE (sensor_id='live' AND status='completed' AND dirty_generation=2) OR (sensor_id='busy' AND status='running' AND dirty_generation=5)`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("repair changed live or leased job count=%d err=%v", count, err)
	}
	// Live work remains ahead of old repaired buckets.
	if _, err = db.Exec(`UPDATE read_model_jobs SET status='pending',dirty_generation=3 WHERE sensor_id='live'`); err != nil {
		t.Fatal(err)
	}
	job, ok, err := s.claimReadModelJob(ctx, []string{activityV3FiveMinuteModel}, "priority-test")
	if err != nil || !ok || job.SensorID != "live" {
		t.Fatalf("repair displaced realtime: job=%+v ok=%v err=%v", job, ok, err)
	}
}

// A device that stops sending traffic must still finalize its last live bucket.
func TestActivityV3QuietBucketSchedulesFinalization(t *testing.T) {
	d := appIntegrationDB(t)
	s, ctx := d.store, context.Background()
	if _, err := s.ensureActivityV3Cutover(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	bucket := now.Truncate(5 * time.Minute)
	sensor := fmt.Sprintf("quiet-finalization-%d", now.UnixNano())
	job := readModelJob{Model: activityV3FiveMinuteModel, BucketStart: bucket, SensorID: sensor, DirtyGeneration: 1}
	t.Cleanup(func() { _, _ = s.pg.db.ExecContext(ctx, "DELETE FROM read_model_jobs WHERE sensor_id=$1", sensor) })
	if _, err := s.pg.db.ExecContext(ctx, `INSERT INTO read_model_jobs(model,bucket_start,sensor_id,campus_id,status,lease_owner,dirty_generation) VALUES($1,$2,$3,'','running','quiet-test',1)`, job.Model, job.BucketStart, sensor); err != nil {
		t.Fatal(err)
	}
	event := normalized.Event{EventID: sensor, SchemaVersion: "1", Source: "test", Type: "dns", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor}, Subject: map[string]any{"ip": "192.0.2.5"}, Payload: map[string]any{"query": "quiet.example"}}
	if err := s.ch.WriteNormalizedEvents(ctx, []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	if err := s.materializeActivityV3FiveMinute(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := s.finishReadModelJob(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	var status string
	var dirty, processed int64
	var notBefore time.Time
	if err := s.pg.db.QueryRowContext(ctx, `SELECT status,dirty_generation,processed_generation,not_before FROM read_model_jobs WHERE model=$1 AND sensor_id=$2`, job.Model, sensor).Scan(&status, &dirty, &processed, &notBefore); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || dirty <= processed || notBefore.Before(bucket.Add(5*time.Minute+90*time.Second)) {
		t.Fatalf("quiet bucket will never finalize without a new receipt: status=%s dirty=%d processed=%d not_before=%s", status, dirty, processed, notBefore)
	}
	// Advance only the replay clock. No new dirty receipt or source packet is
	// written between the live publication and final publication.
	job.DirtyGeneration = dirty
	if err := s.materializeActivityV3FiveMinuteAt(ctx, job, bucket.Add(5*time.Minute+90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.finishReadModelJob(ctx, job, nil); err != nil {
		t.Fatal(err)
	}
	var parents int
	if err := s.pg.db.QueryRowContext(ctx, `SELECT count(*) FROM read_model_jobs WHERE model=$1 AND sensor_id=$2`, activityV3HourModel, sensor).Scan(&parents); err != nil {
		t.Fatal(err)
	}
	if parents != 1 {
		t.Fatalf("quiet finalized bucket failed to enqueue its parent: %d", parents)
	}
	raw, err := s.ch.query(ctx, `SELECT sum(event_count) AS count FROM activity_chart_facts_5m_v3 WHERE sensor_id=`+chQuote(sensor)+` AND dimension='type' AND revision=(SELECT argMax(revision,published_at) FROM activity_chart_bucket_versions_v3 WHERE sensor_id=`+chQuote(sensor)+` AND granularity='5m') FORMAT JSONEachRow`)
	if err != nil {
		t.Fatal(err)
	}
	count, err := decodeSingleCount(raw)
	if err != nil || count != 1 {
		t.Fatalf("final publication lost or duplicated its event: count=%d err=%v", count, err)
	}
}
