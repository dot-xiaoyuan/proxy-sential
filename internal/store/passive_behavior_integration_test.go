package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
)

func TestPassiveBehaviorPostgresCommittedReplayAndRevocation(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not configured")
	}
	t.Setenv("PROXY_SENTINEL_DISCOVERY_CIDRS", "10.42.0.0/24")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	schema := "behavior_test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := db.Exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = db.Close()
	})
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.Exec(statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"014_realtime_ingest_ledger.sql", "251_passive_behavior.sql"} {
		raw, err := os.ReadFile(filepath.Join("../../migrations/postgres", name))
		if err != nil {
			t.Fatal(err)
		}
		exec(string(raw))
	}
	exec(`CREATE TABLE discovery_observations (id text,origin text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,data jsonb);
CREATE TABLE passive_discovery_state (sensor_id text PRIMARY KEY,cursor_timestamp timestamptz NOT NULL)`)
	at := time.Now().UTC().Add(-3 * time.Minute).Truncate(time.Second)
	exec("INSERT INTO passive_discovery_state VALUES ('sensor',$1)", at.Add(-time.Second))
	claims := `{"node":"sensor","site":"campus","domain":"mirror","vlan":"20","ip":"10.42.0.10","mac":"02:11:22:33:44:55"}`
	exec("INSERT INTO discovery_observations VALUES ('arp','arp',$1,$2,false,$3::jsonb)", at.Add(-time.Minute), at.Add(time.Minute), claims)
	exec(`INSERT INTO ingest_batches(batch_id,sensor_id,source_kind,source_path,file_id,start_offset,end_offset,checksum,status,started_at)
 VALUES ('batch','sensor','zeek-conn','conn.log','file',0,10,'digest','started',$1)`, at)
	store := &DBStore{pg: &PostgresStore{db: db}}
	event := normalized.Event{EventID: "dns", SourceEventType: "dns", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor", "interface": "mirror"}, Subject: map[string]any{"campus_id": "campus"}, Payload: map[string]any{"vlan": "20", "query": "vendor.hikvision.com"}, Flow: map[string]any{"src_ip": "10.42.0.10"}}
	flow := event
	flow.EventID, flow.SourceEventType = "flow", "conn"
	flow.Flow = map[string]any{"src_ip": "10.42.0.2", "dst_ip": "10.42.0.10", "proto": "tcp", "dst_port": float64(554), "pkts_toclient": float64(3)}
	flow.Payload = map[string]any{"vlan": "20", "state": "SF"}
	items := []normalized.Event{event, flow}
	batch := ingest.Batch{BatchID: "batch", SensorID: "sensor"}
	if err := store.stagePassiveBehavior(ctx, batch, items); err != nil {
		t.Fatal(err)
	}
	process := func(want bool) {
		t.Helper()
		got, err := store.processPassiveBehavior(ctx, "sensor")
		if err != nil || got != want {
			t.Fatalf("worked=%t want=%t: %v", got, want, err)
		}
	}
	process(false)
	exec("UPDATE ingest_batches SET status='committed',committed_at=$1", at.Add(time.Second))
	process(false)
	exec("UPDATE passive_discovery_state SET cursor_timestamp=$1", at)
	process(true)
	if err := store.stagePassiveBehavior(ctx, batch, items); err != nil {
		t.Fatal(err)
	}
	process(false)
	var firstIngestedAt time.Time
	if err := db.QueryRow("SELECT min(first_ingested_at) FROM passive_behavior_windows").Scan(&firstIngestedAt); err != nil || !firstIngestedAt.Equal(at.Add(time.Second)) {
		t.Fatalf("first commit=%v, err=%v", firstIngestedAt, err)
	}
	key := discovery.PassiveBehaviorKey("sensor", "campus", "mirror", "20", "", "02:11:22:33:44:55", "")
	owner, ok := discovery.ParsePassiveBehaviorKey(key)
	if !ok {
		t.Fatal("invalid generated key")
	}
	result, err := ReadPassiveBehavior(ctx, db, key, owner)
	if err != nil || result.CandidateType != "video_device" || len(result.Items) != 2 {
		t.Fatalf("behavior replay=%+v err=%v", result, err)
	}
	wrongScope := discovery.PassiveBehaviorKey("sensor", "campus", "mirror", "21", "", "02:11:22:33:44:55", "")
	other, _ := discovery.ParsePassiveBehaviorKey(wrongScope)
	if result, err := ReadPassiveBehavior(ctx, db, wrongScope, other); err != nil || len(result.Items) != 0 {
		t.Fatalf("evidence crossed VLAN: %+v %v", result, err)
	}
	unboundKey := discovery.PassiveBehaviorKey("sensor", "campus", "mirror", "20", "", "", "10.42.0.2")
	unbound, _ := discovery.ParsePassiveBehaviorKey(unboundKey)
	if result, err := ReadPassiveBehavior(ctx, db, unboundKey, unbound); err != nil || result.CandidateType != "" || len(result.Items) != 1 || result.Items[0].Kind != "port_attempt" {
		t.Fatalf("unbound port attempt created a type or was omitted: %+v %v", result, err)
	}
	const replayCount = 1024
	replayed := make([]normalized.Event, replayCount)
	for i := range replayed {
		replayed[i] = event
		replayed[i].EventID = "duplicate-" + strconv.Itoa(i)
	}
	exec(`INSERT INTO ingest_batches(batch_id,sensor_id,source_kind,source_path,file_id,start_offset,end_offset,checksum,status,started_at,committed_at)
 VALUES ('replay','sensor','zeek-conn','conn.log','file',10,20,'replay-digest','committed',$1,$1)`, at.Add(time.Minute))
	start := time.Now()
	if err := store.stagePassiveBehavior(ctx, ingest.Batch{BatchID: "replay", SensorID: "sensor"}, replayed); err != nil {
		t.Fatal(err)
	}
	for range replayCount / passiveBehaviorSegmentSize {
		process(true)
	}
	process(false)
	var windowCount, completedSegments int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM passive_behavior_windows),
 (SELECT count(*) FROM passive_behavior_batch_work WHERE batch_id='replay' AND payload='[]'::jsonb AND processed_at IS NOT NULL)`).Scan(&windowCount, &completedSegments); err != nil {
		t.Fatal(err)
	}
	if windowCount != 3 || completedSegments != replayCount/passiveBehaviorSegmentSize {
		t.Fatalf("repeated input grew windows=%d or left segments=%d", windowCount, completedSegments)
	}
	t.Logf("local duplicate replay: %d inputs, %d segments, %d total windows, %s", replayCount, completedSegments, windowCount, time.Since(start))
	exec("INSERT INTO discovery_observations VALUES ('revoke','arp',$1,$1,true,$2::jsonb)", at.Add(-time.Second), claims)
	result, err = ReadPassiveBehavior(ctx, db, key, owner)
	if err != nil || result.CandidateType != "" || len(result.Items) != 0 {
		t.Fatalf("late revocation left a current clue: %+v %v", result, err)
	}
}
