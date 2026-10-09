package store

import (
	"context"
	"encoding/json"
	"os"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestIdentitySignalStreamRetainsSubjectAndReceivesLateEvents(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("isolated ClickHouse required")
	}
	ctx := context.Background()
	if _, e := ApplyClickHouseMigrations(ctx, dsn, "../../migrations/clickhouse"); e != nil {
		t.Fatal(e)
	}
	ch, e := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC().Add(-time.Hour)
	event := normalized.Event{SchemaVersion: "v1", EventID: "identity-late-stream", Type: "identity", Source: "radius", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "identity-stream"}, Subject: map[string]any{"ip": "192.0.2.57", "account_id": "late", "entity_role": "endpoint"}, Payload: map[string]any{"action": "start", "session_id": "source-generation"}, Confidence: .95}
	if e = ch.WriteNormalizedEvents(ctx, []normalized.Event{event}); e != nil {
		t.Fatal(e)
	}
	raw, e := ch.query(ctx, `SELECT * FROM identity_signal_events_v1 WHERE event_id='identity-late-stream' FORMAT JSONEachRow`)
	if e != nil {
		t.Fatal(e)
	}
	events, e := decodeEventRows(raw)
	if e != nil || len(events) != 1 || events[0].Subject["account_id"] != "late" || events[0].Subject["entity_role"] != "endpoint" {
		t.Fatalf("subject lost: %s %v", raw, e)
	}
	var row struct {
		ReceivedAt string `json:"received_at"`
	}
	if e = json.Unmarshal(raw, &row); e != nil {
		t.Fatal(e)
	}
	receipt, e := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.ReceivedAt))
	if e != nil || receipt.Before(at.Add(30*time.Minute)) {
		t.Fatalf("late timestamp used as receipt: %s %v", raw, e)
	}
}
