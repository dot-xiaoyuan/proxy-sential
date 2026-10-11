package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

// The census is the field measurement command for passive device recognition,
// so its denominator and lease counts are verified against a real PostgreSQL
// and ClickHouse pair rather than against a mock.
func TestDeviceCensusAcrossPostgresAndClickHouse(t *testing.T) {
	pgDSN := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	chDSN := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if pgDSN == "" || chDSN == "" {
		t.Skip("isolated postgres and clickhouse required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, pgDSN, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyClickHouseMigrations(ctx, chDSN, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	sensor := fmt.Sprintf("census-replay-%d", time.Now().UnixNano())
	backend, err := NewDBStore(Options{Mode: ModeDB, SensorID: sensor, CollectorKind: "device-census", PostgresDSN: pgDSN, ClickHouseDSN: chDSN, RequestTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	t.Cleanup(func() {
		for _, table := range []string{"normalized_events", "identity_signal_events_v1"} {
			_ = backend.ch.exec(ctx, "ALTER TABLE "+table+" DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2")
		}
		for _, statement := range []string{
			`DELETE FROM device_address_leases WHERE sensor_id=$1`,
			`DELETE FROM sensors WHERE sensor_id=$1`,
		} {
			_, _ = backend.pg.db.ExecContext(ctx, statement, sensor)
		}
	})
	if _, err = backend.pg.db.ExecContext(ctx, `INSERT INTO sensors(sensor_id,display_name,collector_kind) VALUES($1,$1,'zeek') ON CONFLICT(sensor_id) DO NOTHING`, sensor); err != nil {
		t.Fatal(err)
	}
	if _, err = backend.pg.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,observed_at,valid_until,action) VALUES($1,'campus-a','census-lease','198.18.92.10','mac:02:00:00:00:92:10',now(),now()+interval '10 minutes','ack')`, sensor); err != nil {
		t.Fatal(err)
	}
	// One event carries a link-layer address and one does not: the denominator
	// must report the device count and the address count separately.
	now := time.Now().UTC()
	events := []normalized.Event{
		{SchemaVersion: "v1", EventID: "census-1", Source: "zeek", SourceEventType: "conn", Type: "flow", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor}, Subject: map[string]any{"ip": "198.18.92.10", "mac": "02:00:00:00:92:10"}, Flow: map[string]any{"src_ip": "198.18.92.10", "proto": "tcp"}, Payload: map[string]any{}, Confidence: 0.9},
		{SchemaVersion: "v1", EventID: "census-2", Source: "zeek", SourceEventType: "http", Type: "http", Timestamp: now.Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor}, Subject: map[string]any{"ip": "198.18.92.11"}, Flow: map[string]any{"src_ip": "198.18.92.11", "proto": "tcp"}, Payload: map[string]any{"server": "GoAhead-Webs"}, Confidence: 0.9},
	}
	if err = backend.ch.WriteNormalizedEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	census, err := backend.GetDeviceCensus(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if census.ObservedMACs != 1 || census.ObservedIPs != 2 {
		t.Fatalf("unexpected denominator: macs=%d ips=%d errors=%v", census.ObservedMACs, census.ObservedIPs, census.Errors)
	}
	if census.LeasedDevices != 1 {
		t.Fatalf("unexpected leased device count: %d errors=%v", census.LeasedDevices, census.Errors)
	}
	conn, ok := sourceObservability(census, "conn")
	if !ok || conn.EventCount != 1 || conn.MACAttributedCount != 1 {
		t.Fatalf("unexpected conn observability: %+v", census.Recognition.Observability)
	}
	http, ok := sourceObservability(census, "http")
	if !ok || http.MACAttributedCount != 0 {
		t.Fatalf("unexpected http observability: %+v", census.Recognition.Observability)
	}
	if census.Recognition.MACAttributedEventCount != 1 || census.Recognition.MACAttributionRate != 0.5 {
		t.Fatalf("unexpected MAC attribution rate: %+v", census.Recognition)
	}
}

func sourceObservability(census DeviceCensus, source string) (SourceObservability, bool) {
	for _, item := range census.Recognition.Observability {
		if item.SourceEventType == source {
			return item, true
		}
	}
	return SourceObservability{}, false
}
