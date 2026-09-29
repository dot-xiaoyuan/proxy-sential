package store

import (
	"context"
	"encoding/json"
	"os"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestDiscoveryArchiveClickHouse(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("isolated ClickHouse required")
	}
	ctx := context.Background()
	if _, e := ApplyClickHouseMigrations(ctx, dsn, "../../migrations/clickhouse"); e != nil {
		t.Fatal(e)
	}
	s, e := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if e != nil {
		t.Fatal(e)
	}
	event := normalized.Event{SchemaVersion: "v1", EventID: "discovery-archive-replay", Type: "discovery", Source: "snmp", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "discovery-test", "source_id": "switch-test"}, Subject: map[string]any{"mac": "00:11:22:33:44:55", "site": "s", "domain": "d"}, Payload: map[string]any{"origin": "fdb", "ttl": 900}}
	for i := 0; i < 2; i++ {
		if e = s.WriteNormalizedEvents(ctx, []normalized.Event{event}); e != nil {
			t.Fatal(e)
		}
	}
	b, e := s.query(ctx, `SELECT count() AS n FROM normalized_events WHERE event_id='discovery-archive-replay' FORMAT JSONEachRow`)
	if e != nil {
		t.Fatal(e)
	}
	var row struct {
		N int `json:"n"`
	}
	if json.Unmarshal(b, &row) != nil || row.N != 1 {
		t.Fatalf("dedup: %s", b)
	}
}
