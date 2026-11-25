package store

import (
	"context"
	"database/sql"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func verifiedOriginalReplayDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	t.Setenv("PROXY_SENTINEL_PASSIVE_CENSUS_ENABLED", "false")
	return privateMigratedTestPostgres(t).db
}

func TestDHCPOriginalReplayPostgresRollbackResumeAndConcurrentLatest(t *testing.T) {
	db := verifiedOriginalReplayDB(t)
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
	if _, err := db.Exec(`CREATE FUNCTION reject_link() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected link failure'; END $$; CREATE TRIGGER replay_fail BEFORE INSERT ON discovery_identity_links FOR EACH ROW EXECUTE FUNCTION reject_link()`); err != nil {
		t.Fatal(err)
	}
	if _, err := apply(event); err == nil || !strings.Contains(err.Error(), "injected link failure") {
		t.Fatalf("expected injected link failure, got %v", err)
	}
	for _, table := range []string{"discovery_observations", "passive_hardware_facts", "passive_hardware_dirty"} {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("rollback leaked %s rows", table)
		}
	}
	if _, err := db.Exec(`DROP TRIGGER replay_fail ON discovery_identity_links`); err != nil {
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
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("replay expanded %s: %d", table, n)
		}
	}
	newer := event
	newer.Timestamp = at.Add(2 * time.Minute).Format(time.RFC3339Nano)
	newer.EventID = "zeek-" + strings.Repeat("b", 24)
	newer.RawRef = map[string]any{"content_sha256": strings.Repeat("b", 64), "original_file_id": "verified-original"}
	if _, err := apply(newer); err != nil {
		t.Fatal(err)
	}
	if _, err := apply(event); err != nil {
		t.Fatal(err)
	}
	var id, saved, claimedIP string
	var observed, valid time.Time
	if err := db.QueryRow(`SELECT id,data->>'event_id',coalesce(data->>'ip',''),observed_at,valid_until FROM discovery_observation_latest`).Scan(&id, &saved, &claimedIP, &observed, &valid); err != nil {
		t.Fatal(err)
	}
	if saved != event.EventID || claimedIP != "" || !observed.Equal(at.Add(2*time.Minute)) || !valid.Equal(at.Add(12*time.Minute)) {
		t.Fatalf("replay lost compact evidence or moved its clock backwards: event=%s ip=%s observed=%v valid=%v", saved, claimedIP, observed, valid)
	}
	if err := touchPassiveLatest(ctx, db, []map[string]any{{"id": id, "observed_at": observed, "valid_until": observed}}); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT valid_until FROM discovery_observation_latest WHERE id=$1`, id).Scan(&valid); err != nil || !valid.Equal(observed) {
		t.Fatalf("contemporaneous expiry was lost: %v %v", valid, err)
	}
}

func TestRTSPOriginalReplayPostgresIPProductWithoutInventedMAC(t *testing.T) {
	db := verifiedOriginalReplayDB(t)
	event := passiveTestEvent("rtsp", "192.168.0.10", "", map[string]any{"origin": "rtsp", "method": "DESCRIBE", "user_agent": "HIKVISION player NVR V4.74.210", "vlan": "20"})
	event.Source = "zeek"
	event.Timestamp = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	event.EventID = "zeek-" + strings.Repeat("c", 24)
	event.RawRef = map[string]any{"content_sha256": strings.Repeat("c", 64), "original_file_id": "verified-original"}
	event.Flow = map[string]any{"src_ip": "192.168.0.10", "dst_ip": "192.168.0.11", "direction": "client", "dst_port": 554}
	for i := 0; i < 2; i++ {
		rows, err := ApplyRTSPOriginalReplay(context.Background(), db, "office-30", "192.168.0.0/24", []normalized.Event{event})
		if err != nil || len(rows) != 1 || rows[0].Status != "admitted" {
			t.Fatalf("original replay: %+v %v", rows, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM discovery_observations WHERE data->>'ip'='192.168.0.10' AND data->'product_clue'->>'type'='recorder' AND coalesce(data->'product_clue'->>'model','')=''`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("IP product lost or duplicated: %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM passive_hardware_facts`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("IP response invented MAC: %d %v", n, err)
	}
	if _, err := ApplyDHCPMessageReplay(context.Background(), db, "office-30", "192.168.0.0/24", []normalized.Event{event}); err == nil {
		t.Fatal("DHCP mode accepted RTSP")
	}
}
