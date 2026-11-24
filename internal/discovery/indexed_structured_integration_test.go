package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestStructuredDiscoveryPostgresParity(t *testing.T) {
	db := hardwareIntegrationDB(t)
	run := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.Exec(statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("../../migrations/postgres/252_discovery_list_projection.sql")
	if err != nil {
		t.Fatal(err)
	}
	run(string(raw))
	// Exercise the upgrade with pending work already created by the earlier migration.
	run("SELECT discovery_list_dirty_key('concurrent')")
	run("INSERT INTO discovery_list_ip_dirty(sensor_id,device_key,ip,origin) VALUES ('sensor','concurrent','10.0.0.1','arp')")
	raw, err = os.ReadFile("../../migrations/postgres/253_discovery_queue_generations.sql")
	if err != nil {
		t.Fatal(err)
	}
	run(string(raw))
	testConcurrentDiscoveryQueue(t, db)
	at := time.Now().UTC().Truncate(time.Second)
	put := func(id, mac, ip, vlan, origin string, when time.Time) {
		t.Helper()
		o := Observation{ID: id, EventID: id, SourceID: "capture", Node: "sensor", Site: "campus", Domain: "access", VLAN: vlan, MAC: mac, IP: ip, Origin: origin, ObservedAt: when, ValidUntil: at.Add(time.Hour), Confidence: "confirmed", Name: "test-" + id}
		if origin == "snmp" {
			o.ProductClue = &IPProductClue{IP: ip, SensorID: o.Node, Site: o.Site, Domain: o.Domain, VLAN: vlan, EventID: id, Attribution: "response_ip", ProductStatus: "identified", Type: "switch"}
		}
		if origin == "dhcp" {
			o.Evidence.Payload = map[string]any{"dhcp_candidate_type": "mobile"}
		}
		data, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		run("INSERT INTO discovery_observation_latest(id,device_key,origin,observed_at,valid_until,withdrawn,data,service_type) VALUES($1,$2,$3,$4,$5,false,$6,$1)", id, o.Key(), origin, when, o.ValidUntil, data)
	}
	for i := 0; i < 26; i++ {
		put(fmt.Sprint("arp", i), fmt.Sprintf("00:12:34:00:00:%02x", i), "10.0.0.8", "10", "arp", at.Add(-time.Hour))
	}
	put("same-ip-other-vlan", "00:12:34:00:00:00", "10.0.0.8", "20", "arp", at.Add(-4*time.Hour))
	put("dhcp", "00:12:34:00:00:02", "10.0.0.2", "10", "dhcp", at.Add(-2*time.Hour))
	put("product", "", "10.0.0.9", "10", "snmp", at.Add(-time.Minute))
	put("address", "", "10.0.0.10", "10", "ssdp", at.Add(-time.Minute))
	run("INSERT INTO endpoint_recognition_summary VALUES('mac:00:12:34:00:00:04','desktop','Windows','{}',0.8,false,$1)", at)
	run("ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_sync; ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_truncate")
	for done := false; !done; {
		if err := db.QueryRow("SELECT discovery_list_adopt(3)").Scan(&done); err != nil {
			t.Fatal(err)
		}
	}
	refresh := func() {
		t.Helper()
		for i := 0; i < 100; i++ {
			var a, b int
			if err := db.QueryRow("SELECT discovery_list_refresh_groups(5),discovery_list_refresh_ips(7)").Scan(&a, &b); err != nil {
				t.Fatal(err)
			}
			if a+b == 0 {
				return
			}
		}
		t.Fatal("projection did not drain")
	}
	refresh()
	var groups int
	if err := db.QueryRow("SELECT count(*) FROM discovery_list_group_current WHERE hours=24").Scan(&groups); err != nil || groups < 26 {
		t.Fatal(groups, err)
	}
	// A repeated observation touches the structured timestamp without rewriting its evidence.
	run("UPDATE discovery_observation_latest SET observed_at=$1 WHERE id='arp0'", at)
	for _, surface := range []string{"", "list"} {
		t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", surface)
		q := DeviceQuery{Mode: "passive", Window: 24 * time.Hour, Limit: 1, SnapshotAt: at, IdentityScope: "devices"}
		repo := Repository{DB: db, HardwareV2: true}
		page, err := repo.devicesIndexed(context.Background(), db, q, false)
		if err != nil {
			t.Fatal(err)
		}
		first := page["items"].([]DeviceView)
		if len(first) != 1 {
			t.Fatalf("first page has %d rows", len(first))
		}
		if !first[0].LastSeen.Equal(at) {
			t.Fatalf("latest observation time lost: %+v", first[0].LastSeen)
		}
		if first[0].Observations[0].ObservedAt.Equal(at) {
			t.Fatal("retained evidence time was rewritten")
		}
		q.Cursor = page["next_cursor"].(string)
		page, err = repo.devicesIndexed(context.Background(), db, q, false)
		if err != nil || len(page["items"].([]DeviceView)) != 1 || page["items"].([]DeviceView)[0].ID == first[0].ID {
			t.Fatal("cursor lost next page", err)
		}
	}
	compare := func(q DeviceQuery) {
		t.Helper()
		tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := tx.QueryRow("SELECT now()").Scan(&q.SnapshotAt); err != nil {
			t.Fatal(err)
		}
		q.Mode = "passive"
		q.HardwareV2 = true
		read := func(structured, page bool) []string {
			t.Helper()
			q.structured = structured
			q.includeCandidateTypes = !page
			q.includeOverview = !page
			s, err := buildIndexedDeviceSelection(q)
			if err != nil {
				t.Fatal(err)
			}
			statement := s.CTE + ` SELECT identity_key,device_key,last_seen,vlan,classification_status,category,effective_types,product_types,subnets,candidate_role FROM matched ORDER BY identity_key`
			args := s.Args
			if page {
				args = append(slices.Clone(args), 11)
				statement, err = buildHardwareIndexedPage(s, "", fmt.Sprint(len(args)))
				if err != nil {
					t.Fatal(err)
				}
			}
			rows, err := tx.Query("SELECT row_to_json(v)::text FROM ("+statement+") v", args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var out []string
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					t.Fatal(err)
				}
				out = append(out, line)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			return out
		}
		for _, page := range []bool{true, false} {
			a, b := read(false, page), read(true, page)
			if !reflect.DeepEqual(a, b) {
				for i := 0; i < min(len(a), len(b)); i++ {
					if a[i] != b[i] {
						t.Fatalf("page %t row %d\n%s\n%s", page, i, a[i], b[i])
					}
				}
				t.Fatalf("page %t rows %d != %d", page, len(a), len(b))
			}
		}
		coverage := func(surface string) string {
			t.Helper()
			t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", surface)
			var value string
			err := tx.QueryRow("WITH "+coveragePerIPSQL("$1", "$2", "$3", "", "false")+" SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY ip)::text,'[]') FROM per_ip p", "sensor", q.SnapshotAt.Add(-q.Window), q.SnapshotAt).Scan(&value)
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
		if coverage("") != coverage("coverage") {
			t.Fatal("coverage contributions changed")
		}
	}
	for _, scope := range []string{"", "devices", "address_clues"} {
		compare(DeviceQuery{Window: 24 * time.Hour, IdentityScope: scope})
	}
	compare(DeviceQuery{Window: 7 * 24 * time.Hour, Search: "test", VLAN: "10", Protocol: "arp"})
	// Link and profile updates can change identity and classification without
	// changing the latest observation. The projected reader sees both at once.
	run("INSERT INTO discovery_identity_links VALUES('product','mac:00:12:34:00:00:03','{}')")
	run("UPDATE endpoint_recognition_summary SET conflict=true")
	run("UPDATE discovery_observation_latest SET withdrawn=true WHERE id='arp0'")
	put("new-address", "00:12:34:00:00:02", "10.0.0.7", "10", "arp", at)
	compare(DeviceQuery{Window: 24 * time.Hour, IdentityScope: "devices"})
	refresh()
	compare(DeviceQuery{Window: 30 * 24 * time.Hour, IdentityScope: "devices"})
	run("INSERT INTO discovery_identity_links VALUES('arp6','mac:00:12:34:00:00:05','{}')")
	compare(DeviceQuery{Window: 24 * time.Hour, IdentityScope: "devices"})
	run("DELETE FROM discovery_identity_links")
	run("UPDATE discovery_list_group_current SET next_change=now()-interval '1 second' WHERE hours=24")
	refresh()
	var expired int
	if err := db.QueryRow("SELECT count(*) FROM discovery_list_group_current WHERE next_change<=now()").Scan(&expired); err != nil || expired != 0 {
		t.Fatal(expired, err)
	}
	run("UPDATE discovery_observation_latest SET valid_until=now()-interval '1 minute' WHERE id='dhcp'")
	refresh()
	compare(DeviceQuery{Window: 24 * time.Hour})
	run("TRUNCATE discovery_observation_latest")
	var sizes string
	if err := db.QueryRow("SELECT concat_ws(',',(SELECT count(*) FROM discovery_list_observation),(SELECT count(*) FROM discovery_list_group_current),(SELECT count(*) FROM discovery_list_ip_current))").Scan(&sizes); err != nil || strings.TrimSpace(sizes) != "0,0,0" {
		t.Fatal(sizes, err)
	}
}

func testConcurrentDiscoveryQueue(t *testing.T, db *sql.DB) {
	t.Helper()
	var schema string
	if err := db.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	producer, err := sql.Open("pgx", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	tx, err := producer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec("SET LOCAL search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	const enqueue = `SELECT discovery_list_dirty_key('concurrent');
	 INSERT INTO discovery_list_ip_dirty(sensor_id,device_key,ip,origin)
	 VALUES('sensor','concurrent','10.0.0.1','arp') ON CONFLICT DO NOTHING`
	if _, err = tx.Exec(enqueue); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("SET lock_timeout='1s'"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(enqueue); err != nil {
		t.Fatal(err)
	}
	var groups, ips int
	if err = db.QueryRow("SELECT discovery_list_refresh_groups(5),discovery_list_refresh_ips(7)").Scan(&groups, &ips); err != nil || groups < 1 || ips != 2 {
		t.Fatal(groups, ips, err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*),(SELECT count(*) FROM discovery_list_ip_dirty) FROM discovery_list_dirty").Scan(&groups, &ips); err != nil || groups != 1 || ips != 1 {
		t.Fatal(groups, ips, err)
	}
}
