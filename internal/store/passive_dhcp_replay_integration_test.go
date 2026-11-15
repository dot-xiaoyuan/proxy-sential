package store

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func TestDHCPOriginalReplayPostgresRollbackResumeAndConcurrentLatest(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	t.Setenv("PROXY_SENTINEL_PASSIVE_CENSUS_ENABLED", "false")
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("dhcp_raw_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(3)
	t.Cleanup(func() { db.Close(); admin.Exec("DROP SCHEMA " + schema + " CASCADE"); admin.Close() })
	for _, name := range []string{"002_identity_subject_schema.sql", "058_network_discovery.sql", "234_discovery_observations_service_instance.sql", "241_passive_hardware_projection.sql", "242_passive_hardware_claim_index.sql"} {
		raw, err := os.ReadFile("../../migrations/postgres/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	at := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Microsecond)
	event := passiveTestEvent("dhcp", "", "00:11:22:33:44:55", map[string]any{"dhcp_log_kind": "dhcp-message", "msg_types": "REQUEST", "request_only": true, "client_chaddr": "00:11:22:33:44:55", "requested_addr": "192.168.0.99", "vendor_class": "MSFT 5.0", "requested_options": "1,3,6", "dhcp_capture_vlan": "20"})
	event.Source = "zeek"
	event.Timestamp = at.Format(time.RFC3339Nano)
	event.EventID = "zeek-" + strings.Repeat("a", 24)
	event.RawRef = map[string]any{"content_sha256": strings.Repeat("a", 64), "original_file_id": "verified-original"}
	ctx := context.Background()
	apply := func(e normalized.Event) ([]HardwareRepairOutcome, error) {
		return ApplyDHCPMessageReplay(ctx, db, "office-30", "192.168.0.0/24", []normalized.Event{e})
	}
	// Failure after the observation and hardware writes must roll them back.
	if _, err = db.Exec(`CREATE FUNCTION reject_link() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected link failure'; END $$; CREATE TRIGGER replay_fail BEFORE INSERT ON discovery_identity_links FOR EACH ROW EXECUTE FUNCTION reject_link()`); err != nil {
		t.Fatal(err)
	}
	if _, err = apply(event); err == nil {
		t.Fatal("injected failure ignored")
	}
	for _, table := range []string{"discovery_observations", "passive_hardware_facts", "passive_hardware_dirty"} {
		var n int
		db.QueryRow("SELECT count(*) FROM " + table).Scan(&n)
		if n != 0 {
			t.Fatalf("rollback leaked %s rows", table)
		}
	}
	if _, err = db.Exec(`DROP TRIGGER replay_fail ON discovery_identity_links`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		rows, err := apply(event)
		if err != nil || len(rows) != 1 || rows[0].Status != "admitted" {
			t.Fatalf("retry failed: %+v %v", rows, err)
		}
	}
	for _, table := range []string{"discovery_observations", "passive_hardware_facts", "passive_hardware_dirty"} {
		var n int
		db.QueryRow("SELECT count(*) FROM " + table).Scan(&n)
		if n != 1 {
			t.Fatalf("replay expanded %s: %d", table, n)
		}
	}
	newer := event
	newer.Timestamp = at.Add(2 * time.Minute).Format(time.RFC3339Nano)
	newer.EventID = "zeek-" + strings.Repeat("b", 24)
	newer.RawRef = map[string]any{"content_sha256": strings.Repeat("b", 64), "original_file_id": "verified-original"}
	if _, err = apply(newer); err != nil {
		t.Fatal(err)
	}
	if _, err = apply(event); err != nil {
		t.Fatal(err)
	}
	var saved string
	db.QueryRow(`SELECT data->>'event_id' FROM discovery_observations`).Scan(&saved)
	if saved != newer.EventID {
		t.Fatal("late historical replay replaced newer observation")
	}
	var claimedIP string
	db.QueryRow(`SELECT coalesce(data->>'ip','') FROM discovery_observations`).Scan(&claimedIP)
	if claimedIP != "" {
		t.Fatal("request created address lease")
	}
}
