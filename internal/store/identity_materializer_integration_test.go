package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIdentityMaterializerReceiptCursorAtomicAndLateReplay(t *testing.T) {
	pg, ctx := ownedRiskFreshnessReplayStore(t)
	pg.sensorID = "identity-replay"
	at := time.Now().UTC().Add(-10 * time.Minute)
	receipt := at.Add(time.Minute)
	_, err := pg.db.Exec(`INSERT INTO identity_materializer_cursors(sensor_id,phase,cursor_at,cutover_at) VALUES('identity-replay','live',$1,$1)`, at)
	if err != nil {
		t.Fatal(err)
	}
	bad := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := "192.0.2.58"
		if bad {
			ip = "invalid IP"
		}
		row := map[string]any{"received_at": receipt.Format(time.RFC3339Nano), "timestamp": at.Add(-time.Hour).Format(time.RFC3339Nano), "event_id": "late-identity", "schema_version": "v1", "source": "radius", "source_event_type": "accounting", "type": "identity", "sensor_id": "identity-replay", "subject_ip": ip, "subject_json": fmt.Sprintf(`{"ip":%q,"account_id":"late-account","entity_role":"endpoint"}`, ip), "observer_json": `{"sensor_id":"identity-replay"}`, "payload_json": `{"session_id":"late-login","action":"start","session_status":"start"}`, "flow_json": "{}", "raw_ref_json": "{}", "confidence": .95}
		json.NewEncoder(w).Encode(row)
	}))
	defer server.Close()
	backend := &DBStore{pg: pg, ch: &ClickHouseStore{dsn: server.URL, client: server.Client()}}
	if _, err = backend.processIdentitySignalBatch(ctx, "live"); err == nil {
		t.Fatal("invalid identity committed")
	}
	var cursor time.Time
	if err = pg.db.QueryRow(`SELECT cursor_at FROM identity_materializer_cursors WHERE sensor_id='identity-replay' AND phase='live'`).Scan(&cursor); err != nil || !cursor.Equal(at.Truncate(time.Microsecond)) {
		t.Fatalf("failed batch advanced: %s %v", cursor, err)
	}
	bad = false
	for i := 0; i < 2; i++ {
		if _, err = backend.processIdentitySignalBatch(context.Background(), "live"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = pg.db.QueryRow(`SELECT count(*) FROM identity_ip_mac_history WHERE event_id='late-identity'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("non-idempotent late replay: %d %v", count, err)
	}
	if err = pg.db.QueryRow(`SELECT cursor_at FROM identity_materializer_cursors WHERE sensor_id='identity-replay' AND phase='live'`).Scan(&cursor); err != nil || !cursor.Equal(receipt.Truncate(time.Microsecond)) {
		t.Fatalf("receipt cursor missing: %s %v", cursor, err)
	}
}

func TestIdentityMaterializerEmptyPartitionResumesFromDurableCursor(t *testing.T) {
	pg, ctx := ownedRiskFreshnessReplayStore(t)
	pg.sensorID = "partition-replay"
	start := time.Now().UTC().Truncate(24 * time.Hour).Add(-72 * time.Hour)
	next := start.Add(24 * time.Hour)
	if _, err := pg.db.Exec(`INSERT INTO identity_materializer_cursors(sensor_id,phase,cursor_at,cutover_at) VALUES('partition-replay','backfill',$1,$2)`, start, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		query, _ := io.ReadAll(r.Body)
		upper := next
		if requestCount > 1 {
			upper = next.Add(24 * time.Hour)
		}
		if !strings.Contains(string(query), "received_at<=parseDateTime64BestEffort('"+upper.Format(time.RFC3339Nano)+"',6)") {
			t.Errorf("unbounded partition read: %s", query)
		}
	}))
	defer server.Close()
	backend := &DBStore{pg: pg, ch: &ClickHouseStore{dsn: server.URL, client: server.Client()}}
	if n, err := backend.processIdentitySignalBatch(ctx, "backfill"); err != nil || n != 0 {
		t.Fatalf("empty partition failed: %d %v", n, err)
	}
	// Recreate the worker to prove restart resumes from PostgreSQL progress.
	backend = &DBStore{pg: pg, ch: &ClickHouseStore{dsn: server.URL, client: server.Client()}}
	if n, err := backend.processIdentitySignalBatch(ctx, "backfill"); err != nil || n != 0 {
		t.Fatalf("restart failed: %d %v", n, err)
	}
	var cursor time.Time
	if err := pg.db.QueryRow(`SELECT cursor_at FROM identity_materializer_cursors WHERE sensor_id='partition-replay' AND phase='backfill'`).Scan(&cursor); err != nil || !cursor.Equal(next.Add(24*time.Hour)) {
		t.Fatalf("empty partitions did not advance durably: %s %v", cursor, err)
	}
}
