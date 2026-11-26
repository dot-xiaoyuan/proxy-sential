package discovery

import (
	"context"
	"crypto/sha256"
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
	raw, err = os.ReadFile("../../migrations/postgres/254_discovery_address_links_and_reports.sql")
	if err != nil {
		t.Fatal(err)
	}
	run(string(raw))
	applyDiscoveryTestSQL(t, db, "256_discovery_page_indexes.sql")
	var ready bool
	if err := db.QueryRow("SELECT discovery_address_links_ready()").Scan(&ready); err != nil || ready {
		t.Fatal(ready, err)
	}
	run("ALTER TABLE discovery_list_observation ENABLE TRIGGER discovery_address_fact; ALTER TABLE discovery_list_observation ENABLE TRIGGER discovery_address_fact_clear; ALTER TABLE discovery_identity_links ENABLE TRIGGER discovery_address_identity; ALTER TABLE discovery_identity_links ENABLE TRIGGER discovery_address_identity_clear")
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
	put("second-product", "", "10.0.0.9", "10", "snmp", at.Add(-2*time.Minute))
	run(`UPDATE discovery_observation_latest SET data=jsonb_set(data,'{product_clue,type}','"printer"') WHERE id='second-product'`)
	put("also-product", "00:12:34:00:00:04", "10.0.0.8", "10", "snmp", at.Add(-2*time.Minute))
	put("conflicting-product", "00:12:34:00:00:0b", "10.0.0.8", "10", "snmp", at.Add(-2*time.Minute))
	run(`UPDATE discovery_observation_latest SET data=jsonb_set(data,'{product_clue}',((data->'product_clue')-'type')||'{"product_status":"conflict","conflicting_types":["router","switch"]}'::jsonb) WHERE id='conflicting-product'`)
	put("model-without-type", "00:12:34:00:00:0c", "10.0.0.8", "10", "snmp", at.Add(-2*time.Minute))
	run(`UPDATE discovery_observation_latest SET data=jsonb_set(data,'{product_clue}',((data->'product_clue')-'type')||'{"product_status":"no_type_match","model":"AB-100"}'::jsonb) WHERE id='model-without-type'`)
	put("mac-without-ip", "00:12:34:00:00:f1", "", "10", "arp", at.Add(-3*time.Minute))
	put("address", "", "10.0.0.10", "10", "ssdp", at.Add(-time.Minute))
	run("INSERT INTO endpoint_recognition_summary VALUES('mac:00:12:34:00:00:04','desktop','Windows','{}',0.8,false,$1)", at)
	put("binding-arp", "00:12:34:00:00:f0", "10.0.0.80", "30", "arp", at.Add(-2*time.Hour))
	put("binding-sadp", "", "10.0.0.80", "30", "sadp", at.Add(-time.Hour))
	run(`UPDATE discovery_observation_latest SET data=data||jsonb_build_object('evidence',jsonb_build_object('payload',jsonb_build_object('claimed_mac','00:12:34:00:00:f0','claimed_ip','10.0.0.80','identity_status','l2_mismatch'))) WHERE id='binding-sadp'`)
	put("noncanonical-lease", "ff:00:00:00:00:f0", "10.0.0.100", "30", "arp", at.Add(-2*time.Hour))
	run("INSERT INTO device_address_leases VALUES('noncanonical-lease','ack','sensor','10.0.0.100','','mac:ff:00:00:00:00:f0')")
	put("uppercase-profile", "00:12:34:00:00:ea", "10.0.0.102", "33", "arp", at.Add(-2*time.Hour))
	run("INSERT INTO discovery_identity_links VALUES('uppercase-profile','MAC:00:12:34:00:00:EA','{}')")
	run("INSERT INTO endpoint_recognition_summary VALUES('MAC:00:12:34:00:00:EA','printer','','{}',0.8,false,$1)", at)
	run("ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_sync; ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_truncate")
	for done := false; !done; {
		if err := db.QueryRow("SELECT discovery_list_adopt(3)").Scan(&done); err != nil {
			t.Fatal(err)
		}
	}
	refresh := func() {
		t.Helper()
		for i := 0; i < 100; i++ {
			var a, b, c int
			if err := db.QueryRow("SELECT discovery_list_refresh_groups(5),discovery_list_refresh_ips(7), discovery_address_links_refresh(2)").Scan(&a, &b, &c); err != nil {
				t.Fatal(err)
			}
			if a+b+c == 0 {
				return
			}
		}
		t.Fatal("projection did not drain")
	}
	refresh()
	run(`INSERT INTO passive_hardware_current(identity_key,scope_key,device_key,sensor_id,campus_id,access_domain,mac,hardware_type,hardware_type_status,first_seen,last_seen,active_until,data)
      SELECT base_identity,'scope',device_key,sensor_id,site_id,access_domain,raw_mac,'printer',status,observed_at,observed_at,valid_until,
        jsonb_build_object('hardware_type','printer','hardware_type_status',status,'first_seen',observed_at,'last_seen',observed_at)
      FROM discovery_list_observation CROSS JOIN LATERAL (SELECT CASE id WHEN 'arp1' THEN 'identified' WHEN 'arp9' THEN 'conflict' ELSE 'revoked' END status) s WHERE id IN ('arp1','arp7','arp9')`)
	var groups int
	if err := db.QueryRow("SELECT count(*) FROM discovery_list_group_current WHERE hours=24").Scan(&groups); err != nil || groups < 26 {
		t.Fatal(groups, err)
	}
	// A repeated observation touches the structured timestamp without rewriting its evidence.
	run("UPDATE discovery_observation_latest SET observed_at=$1 WHERE id='arp0'", at)
	t.Run("TypeEvidencePartitions", func(t *testing.T) { checkTypeEvidencePartitions(t, db, at) })
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
		t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", "list,coverage,address_links")
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
		q.Limit = 7
		q.structured = true
		t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", "list,address_links,ordered_pages")
		if orderedPageEnabled(q) {
			compareOrderedPages(t, tx, q)
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
	for _, kind := range []string{"mobile", "desktop", "switch", "switch,desktop", "printer"} {
		compare(DeviceQuery{Window: 24 * time.Hour, DeviceType: kind, IdentityScope: "devices"})
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
	run("UPDATE discovery_identity_links SET endpoint_id='mac:00:12:34:00:00:05' WHERE observation_id='product'")
	compare(DeviceQuery{Window: 24 * time.Hour, IdentityScope: "devices"})
	compare(DeviceQuery{Window: 24 * time.Hour, DeviceType: "switch", IdentityScope: "devices"})
	run("DELETE FROM discovery_identity_links")
	compare(DeviceQuery{Window: 24 * time.Hour, IdentityScope: "devices"})
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

func checkTypeEvidencePartitions(t *testing.T, db *sql.DB, at time.Time) {
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	repo := Repository{HardwareV2: true}
	for _, flags := range []string{"", "list,statistics,address_links", "list,statistics,address_links,ordered_pages,cross_vlan"} {
		t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", flags)
		q := DeviceQuery{Mode: "passive", IdentityScope: "devices", Window: 24 * time.Hour, SnapshotAt: at, Limit: 200}
		read := func(state string, export bool) []DeviceView {
			t.Helper()
			q.State, q.Export = state, export
			page, err := repo.DevicesIndexedSnapshot(ctx, tx, q)
			if err != nil {
				t.Fatal(flags, state, err)
			}
			return page["items"].([]DeviceView)
		}
		list := read("", false)
		if exported := read("", true); !reflect.DeepEqual(exported, list) {
			t.Fatalf("list/export mismatch with %q", flags)
		}
		meta, err := repo.DevicesIndexedMetadataSnapshot(ctx, tx, q)
		if err != nil {
			t.Fatal(flags, err)
		}
		if meta.Total != int64(len(list)) || meta.Total != meta.Identified+meta.Candidate+meta.Conflict+meta.Expired ||
			meta.Candidate != meta.ProfileTyped+meta.IPProductOnly+meta.NoTypeClue || meta.Revoked != 1 || meta.Conflict != 1 {
			t.Fatalf("unclosed evidence counts %s: %+v %+v", flags, meta, meta.IndexedTypeEvidenceCounts)
		}
		counts := map[string]int64{"identified": meta.Identified, "profile_typed": meta.ProfileTyped, "ip_product_only": meta.IPProductOnly, "no_type_clue": meta.NoTypeClue, "revoked": meta.Revoked, "conflict": meta.Conflict}
		for state, n := range counts {
			filtered := read(state, false)
			if n == 0 || int64(len(filtered)) != n {
				t.Fatalf("%s %s got %d rows, metadata %d", flags, state, len(filtered), n)
			}
			for _, row := range filtered {
				if row.TypeEvidenceState != state {
					t.Fatalf("%s filter %s admitted %s", flags, state, row.TypeEvidenceState)
				}
			}
		}
		if n := len(read("candidate", false)); int64(n) != meta.Candidate {
			t.Fatal("legacy candidate union", flags, n, meta.Candidate)
		}
		if n := len(read("ip_product_only,revoked", false)); int64(n) != meta.IPProductOnly+meta.Revoked {
			t.Fatal("multi-select union", flags, n)
		}
		for state, facets := range map[string][]IndexedDeviceTypeCount{"profile_typed": meta.CandidateTypes, "ip_product_only": meta.IPProductTypes} {
			for _, facet := range facets {
				q.DeviceType = facet.DeviceType
				if got := len(read(state, false)); int64(got) != facet.Count {
					t.Fatalf("%s %s/%s selected %d rows, facet %d", flags, state, facet.DeviceType, got, facet.Count)
				}
			}
		}
		q.DeviceType = "switch"
		if got := len(read("profile_typed", false)); got != 0 {
			t.Fatalf("%s matched %d profiles by their independent IP product type", flags, got)
		}
		if got := len(read("candidate", false)); got != 2 {
			t.Fatalf("%s legacy candidate/switch broad match: %d", flags, got)
		}
		// The DHCP-only candidate, the profiled identity with IP product evidence,
		// and the identity with two mutually exclusive IP reports each count once.
		witness := map[string]string{"dhcp": "profile_typed", "also-product": "profile_typed", "second-product": "ip_product_only", "conflicting-product": "ip_product_only", "model-without-type": "no_type_clue", "mac-without-ip": "no_type_clue"}
		for _, row := range list {
			for _, o := range row.Observations {
				if want, ok := witness[o.ID]; ok {
					if row.TypeEvidenceState != want || (want == "profile_typed") != (row.CandidateDeviceType != "") || row.DeviceType != "" {
						t.Fatalf("%s %s: state=%s candidate=%s confirmed=%s", flags, o.ID, row.TypeEvidenceState, row.CandidateDeviceType, row.DeviceType)
					}
					delete(witness, o.ID)
				}
			}
		}
		if len(witness) != 0 {
			t.Fatalf("missing fixture identities: %v", witness)
		}
	}
}

// Compare the serialized response, including display enrichment, cursors and
// page-level facets, and compare every admitted identity with the statistics.
func compareOrderedPages(t *testing.T, tx *sql.Tx, q DeviceQuery) {
	t.Helper()
	q.includeOverview = false
	q.includeCandidateTypes = true
	s, err := buildIndexedDeviceSelection(q)
	if err != nil {
		t.Fatal(err)
	}
	var expected int
	if err := tx.QueryRow(s.CTE+" SELECT count(*) FROM matched", s.Args...).Scan(&expected); err != nil {
		t.Fatal(err)
	}
	q.includeCandidateTypes = false
	repo := Repository{HardwareV2: true}
	count := 0
	combined := sha256.New()
	for {
		pages := [][]byte{}
		var cursor string
		for _, flag := range []string{"list,address_links", "list,address_links,ordered_pages"} {
			t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", flag)
			p, err := repo.devicesIndexed(context.Background(), tx, q, false)
			if err != nil {
				t.Fatalf("%s: %v", flag, err)
			}
			encoded, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			pages = append(pages, encoded)
			cursor = p["next_cursor"].(string)
			if flag == "list,address_links,ordered_pages" {
				count += len(p["items"].([]DeviceView))
			}
		}
		if sha256.Sum256(pages[0]) != sha256.Sum256(pages[1]) {
			t.Fatalf("page digest mismatch for scope %s type %s after %s: %x %x", q.IdentityScope, q.DeviceType, q.Cursor, sha256.Sum256(pages[0]), sha256.Sum256(pages[1]))
		}
		combined.Write(pages[0])
		if cursor == "" {
			break
		}
		if cursor == q.Cursor || count > expected {
			t.Fatalf("nonadvancing page: %s", cursor)
		}
		q.Cursor = cursor
	}
	t.Logf("ordered parity scope=%q type=%q hours=%g rows=%d complete_page_sha256=%x", q.IdentityScope, q.DeviceType, q.Window.Hours(), count, combined.Sum(nil))
	if count != expected {
		t.Fatalf("scope %s type %s: got %d rows, statistics %d", q.IdentityScope, q.DeviceType, count, expected)
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
