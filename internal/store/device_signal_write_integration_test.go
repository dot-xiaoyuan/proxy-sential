package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestDeviceSignalBatchCoalescesWritesAndKeepsSamples(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires owned isolated database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE device_signal_facts (
 sensor_id text NOT NULL, signal_id text NOT NULL, ip inet NOT NULL, source text NOT NULL,
 kind text NOT NULL, value text NOT NULL, normalized_value text NOT NULL, strength text NOT NULL,
 confidence double precision NOT NULL, weight integer NOT NULL, first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL, seen_count integer NOT NULL, event_ids_sample jsonb,
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(sensor_id,signal_id))`); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	signal := DeviceSignal{SignalID: "signal-a", IP: "192.0.2.1", Source: "ncu", Kind: "mac",
		Value: "02:00:00:00:00:01", NormalizedValue: "02:00:00:00:00:01", Strength: "strong",
		Confidence: 0.8, Weight: 10, FirstSeen: base.Format(time.RFC3339), LastSeen: base.Format(time.RFC3339),
		EventIDs: []string{"event-a"}}
	if err := upsertDeviceSignalFactsBatch(ctx, tx, "sensor-a", []DeviceSignal{signal}); err != nil {
		t.Fatal(err)
	}
	var tupleBefore string
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT ctid::text,seen_count FROM device_signal_facts WHERE signal_id='signal-a'`).Scan(&tupleBefore, &count); err != nil || count != 1 {
		t.Fatalf("first signal write: tuple=%s count=%d err=%v", tupleBefore, count, err)
	}
	// Reobserving the same fact without a new event sample must not create a new tuple.
	signal.EventIDs = nil
	if err := upsertDeviceSignalFactsBatch(ctx, tx, "sensor-a", []DeviceSignal{signal}); err != nil {
		t.Fatal(err)
	}
	var tupleAfter string
	if err := tx.QueryRowContext(ctx, `SELECT ctid::text,seen_count FROM device_signal_facts WHERE signal_id='signal-a'`).Scan(&tupleAfter, &count); err != nil || tupleAfter != tupleBefore || count != 1 {
		t.Fatalf("unchanged signal rewrote row: before=%s after=%s count=%d err=%v", tupleBefore, tupleAfter, count, err)
	}
	signal.EventIDs = []string{"event-b"}
	signal.LastSeen = base.Add(time.Minute).Format(time.RFC3339)
	if err := upsertDeviceSignalFactsBatch(ctx, tx, "sensor-a", []DeviceSignal{signal}); err != nil {
		t.Fatal(err)
	}
	var sample []byte
	var last time.Time
	if err := tx.QueryRowContext(ctx, `SELECT seen_count,event_ids_sample,last_seen FROM device_signal_facts WHERE signal_id='signal-a'`).Scan(&count, &sample, &last); err != nil {
		t.Fatal(err)
	}
	var ids []string
	if err := json.Unmarshal(sample, &ids); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if count != 2 || !last.Equal(base.Add(time.Minute)) || !seen["event-a"] || !seen["event-b"] {
		t.Fatalf("signal sample changed: count=%d last=%v ids=%v", count, last, ids)
	}
}
