package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func TestPassiveMDNSRepeatedWithdrawalDoesNotRewriteHistory(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	store := &DBStore{pg: pg}
	at := time.Now().UTC().Truncate(time.Second)
	sensor, iface := "withdraw-test", "mirror"
	for _, tc := range []struct{ kind, name, value, ip, instance string }{
		{"A", "printer.local", "192.168.50.10", "192.168.50.10", ""},
		{"SRV", "printer._ipp._tcp.local", "printer.local", "192.168.50.10", "printer._ipp._tcp.local"},
		{"PTR", "_ipp._tcp.local", "printer._ipp._tcp.local", "192.168.50.10", "printer._ipp._tcp.local"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			id := fmt.Sprintf("mdns-withdraw-%s-%d", tc.kind, at.UnixNano())
			source := "passive:" + sensor + ":" + iface
			observation := discovery.Observation{ID: id, SourceID: source, Origin: "dns_sd", IP: tc.ip, ObservedAt: at, ValidUntil: at.Add(time.Hour), Evidence: normalized.Event{Payload: map[string]any{"service_instance": tc.instance}}}
			raw, _ := json.Marshal(observation)
			if _, err := pg.db.ExecContext(ctx, `INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$1,$2,'dns_sd',$3,$4,false,$5)`, id, source, at, observation.ValidUntil, raw); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = pg.db.ExecContext(ctx, `DELETE FROM discovery_observations WHERE id=$1`, id) })
			event := normalized.Event{Timestamp: at.Add(time.Minute).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor, "interface": iface}, Payload: map[string]any{"is_response": true, "record_type": tc.kind, "record_name": tc.name, "record_address": tc.value, "service_target": tc.value, "record_ttl": 0}}
			scope, _ := parsePassiveDiscoveryScope("192.168.0.0/16")
			if _, _, err := store.materializeMDNS(ctx, pg.db, event, scope); err != nil {
				t.Fatal(err)
			}
			var firstCTID, secondCTID string
			var withdrawn bool
			var until time.Time
			if err := pg.db.QueryRowContext(ctx, `SELECT ctid::text,withdrawn,valid_until FROM discovery_observations WHERE id=$1`, id).Scan(&firstCTID, &withdrawn, &until); err != nil || !withdrawn || !until.Equal(at.Add(time.Minute)) {
				t.Fatalf("first withdrawal: withdrawn=%v until=%s err=%v", withdrawn, until, err)
			}
			event.Timestamp = at.Add(2 * time.Minute).Format(time.RFC3339Nano)
			if _, _, err := store.materializeMDNS(ctx, pg.db, event, scope); err != nil {
				t.Fatal(err)
			}
			if err := pg.db.QueryRowContext(ctx, `SELECT ctid::text FROM discovery_observations WHERE id=$1`, id).Scan(&secondCTID); err != nil || firstCTID != secondCTID {
				t.Fatalf("repeated withdrawal rewrote history: before=%s after=%s err=%v", firstCTID, secondCTID, err)
			}
		})
	}
}
