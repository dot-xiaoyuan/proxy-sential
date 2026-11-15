package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestMDNSScopedCacheJoinsWithdrawalsAndReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("mdns_scope_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + ";SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	for _, name := range []string{"058_network_discovery.sql", "249_mdns_scoped_cache.sql"} {
		raw, err := os.ReadFile("../../migrations/postgres/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	s := &DBStore{}
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/24")
	at := time.Now().UTC().Truncate(time.Second)
	event := func(vlan, vrf, kind, name, value string, offset int, ttl int) normalized.Event {
		return normalized.Event{EventID: fmt.Sprintf("%s-%s-%s-%d", vlan, vrf, kind, offset), Source: "zeek", SourceEventType: "mdns", Timestamp: at.Add(time.Duration(offset) * time.Second).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": "sensor", "interface": "mirror"}, Subject: map[string]any{"ip": "10.0.0.2"}, Flow: map[string]any{"src_ip": "10.0.0.2", "dst_ip": "224.0.0.251"}, Payload: map[string]any{"vlan": vlan, "vrf": vrf, "is_response": true, "record_type": kind, "record_name": name, "record_address": value, "service_target": value, "record_text": value, "record_ttl": ttl, "l2_source_mac_direct": true, "responder_l2_mac": "00:11:22:33:44:55"}, RawRef: map[string]any{"content_sha256": "test-reference"}}
	}
	apply := func(e normalized.Event) []discovery.Observation {
		t.Helper()
		o, _, err := s.materializeMDNS(ctx, db, e, scope)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	apply(event("2701/26", "blue", "TXT", "tv._raop._tcp.local", "am=AppleTV3,1", 0, 120))
	apply(event("2701/26", "blue", "SRV", "tv._raop._tcp.local", "tv.local", 1, 120))
	for _, pair := range [][2]string{{"2701/27", "blue"}, {"2701/26", "red"}, {"", "blue"}} {
		if o := apply(event(pair[0], pair[1], "A", "tv.local", "10.0.0.3", 2, 120)); len(o) != 0 {
			t.Fatalf("cross-scope join: %+v", o)
		}
	}
	joined := apply(event("2701/26", "blue", "A", "tv.local", "10.0.0.3", 3, 120))
	if len(joined) != 1 || joined[0].VLAN != "2701/26" || joined[0].VRF != "blue" || joined[0].ModelName != "AppleTV3,1" || joined[0].MAC != "" {
		t.Fatalf("bad own-scope join: %+v", joined)
	}
	if joined[0].Evidence.RawRef["records"] == nil {
		t.Fatal("join lost raw references")
	}
	// Persist two same-address rows, then withdraw only the matching scope.
	for _, vlan := range []string{"2701/26", "2701/27"} {
		o := joined[0]
		o.ID = "obs-" + vlan
		o.VLAN = vlan
		raw, _ := json.Marshal(o)
		if _, err = db.Exec(`INSERT INTO discovery_observations VALUES($1,$1,$2,'dns_sd',$3,$4,false,$5)`, o.ID, o.SourceID, o.ObservedAt, o.ValidUntil, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	bye := event("2701/26", "blue", "A", "tv.local", "10.0.0.3", 10, 0)
	apply(bye)
	var withdrawn, other bool
	if err = db.QueryRow(`SELECT (SELECT withdrawn FROM discovery_observations WHERE id='obs-2701/26'),(SELECT withdrawn FROM discovery_observations WHERE id='obs-2701/27')`).Scan(&withdrawn, &other); err != nil || !withdrawn || other {
		t.Fatalf("cross-scope withdrawal: %v %v %v", withdrawn, other, err)
	}
	// Late positive and duplicate bye neither resurrect nor rewrite the tombstone.
	var before, after string
	q := `SELECT ctid::text FROM passive_discovery_mdns_scoped_records WHERE scope_key=$1 AND record_type='A'`
	if err = db.QueryRow(q, passiveMDNSScopeKey(bye)).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if o := apply(event("2701/26", "blue", "A", "tv.local", "10.0.0.3", 5, 120)); len(o) != 0 {
		t.Fatal("late positive revived withdrawal")
	}
	apply(bye)
	if err = db.QueryRow(q, passiveMDNSScopeKey(bye)).Scan(&after); err != nil || before != after {
		t.Fatal("repeat changed tombstone", err)
	}
	// Transaction rollback leaves no partial cache mutation.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.materializeMDNS(ctx, tx, event("100", "", "TXT", "new._raop._tcp.local", "am=AppleTV3,1", 20, 120), scope); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	var n int
	db.QueryRow(`SELECT count(*) FROM passive_discovery_mdns_scoped_records WHERE record_name='new._raop._tcp.local'`).Scan(&n)
	if n != 0 {
		t.Fatal("rollback leaked cache row")
	}
	// Bounded growth: refreshing the same RR 100 times retains one row.
	for i := 21; i < 121; i++ {
		apply(event("100", "", "TXT", "new._raop._tcp.local", "am=AppleTV3,1", i, 120))
	}
	db.QueryRow(`SELECT count(*) FROM passive_discovery_mdns_scoped_records WHERE record_name='new._raop._tcp.local'`).Scan(&n)
	if n != 1 {
		t.Fatalf("repeat cache growth: %d", n)
	}
	old := event("100", "", "TXT", "old._raop._tcp.local", "am=AppleTV3,1", -40*86400, 120)
	apply(old)
	if err = expireMDNSScopedCache(ctx, db, []normalized.Event{bye}); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT count(*) FROM passive_discovery_mdns_scoped_records WHERE record_name='old._raop._tcp.local'`).Scan(&n)
	if n != 0 {
		t.Fatal("expired cache retained")
	}
}
