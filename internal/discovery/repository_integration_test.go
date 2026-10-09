package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestPostgresDiscoveryReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	ctx := context.Background()
	ddl, e := os.ReadFile("../../migrations/postgres/058_network_discovery.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(ctx, string(ddl)); e != nil {
		t.Fatal(e)
	}
	ddl, e = os.ReadFile("../../migrations/postgres/083_discovery_latest.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(ctx, string(ddl)); e != nil {
		t.Fatal(e)
	}
	r := Repository{DB: db}
	s := Source{ID: "replay", Node: "test", Site: "s", Domain: "d", ConfigVersion: 1, IntervalSeconds: 300}
	b, _ := json.Marshal(s)
	if _, e = db.ExecContext(ctx, `INSERT INTO discovery_sources(id,node,config,encrypted_secret) VALUES('replay','test',$1,'test') ON CONFLICT DO NOTHING`, b); e != nil {
		t.Fatal(e)
	}
	if e = r.EnqueuePoll(ctx, "task-a", "replay"); e != nil {
		t.Fatal(e)
	}
	if e = r.EnqueuePoll(ctx, "task-b", "replay"); e == nil {
		t.Fatal("duplicate task allowed")
	}
	task, e := r.Claim(ctx, "test")
	if e != nil || task.ID != "task-a" {
		t.Fatalf("claim: %+v %v", task, e)
	}
	now := time.Now().UTC()
	event := normalized.Event{SchemaVersion: "v1", EventID: "obs1", Type: "discovery", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"source_id": "replay", "sensor_id": "test"}, Subject: map[string]any{"site": "s", "domain": "d", "mac": "00:11:22:33:44:55", "vlan": "10"}, Payload: map[string]any{"origin": "fdb", "ttl": 300}}
	snap := Snapshot{ID: "snap1", SourceID: "replay", At: now, Events: []normalized.Event{event, event}}
	for i := 0; i < 2; i++ {
		if e = r.SaveSnapshot(ctx, snap); e != nil {
			t.Fatal(e)
		}
	}
	page, e := r.Devices(ctx, 20, 0)
	if e != nil || page["total"] != 1 {
		t.Fatalf("dedup: %v %v", page, e)
	}
	event.EventID = "obs2"
	event.Timestamp = now.Add(time.Millisecond).Format(time.RFC3339Nano)
	event.Subject["vlan"] = "20"
	snap.ID = "snap2"
	snap.Events = []normalized.Event{event}
	if e = r.SaveSnapshot(ctx, snap); e != nil {
		t.Fatal(e)
	}
	time.Sleep(3 * time.Millisecond)
	page, e = r.Devices(ctx, 1, 0)
	if e != nil || page["total"] != 2 {
		t.Fatalf("scope/page: %v %v", page, e)
	}
	if _, e = db.ExecContext(ctx, `UPDATE discovery_tasks SET cancel_requested=true WHERE id=$1`, task.ID); e != nil {
		t.Fatal(e)
	}
	if e = r.Finish(ctx, task, snap, nil); e != nil {
		t.Fatal(e)
	}

	var status string
	if e = db.QueryRowContext(ctx, `SELECT status FROM discovery_tasks WHERE id=$1`, task.ID).Scan(&status); e != nil || status != "cancelled" {
		t.Fatalf("cancel %s %v", status, e)
	}
	if e = r.EnqueuePoll(ctx, "task-retry", "replay"); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Claim(ctx, "test"); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(ctx, `UPDATE discovery_tasks SET lease_until=now()-interval '1 second' WHERE id='task-retry'`); e != nil {
		t.Fatal(e)
	}
	retry, e := r.Claim(ctx, "test")
	if e != nil || retry.ID != "task-retry" {
		t.Fatalf("lease retry %v %v", retry, e)
	}
}
