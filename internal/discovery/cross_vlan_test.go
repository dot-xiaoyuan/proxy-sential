package discovery

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCrossVLANDiscoveryWindow(t *testing.T) {
	db := hardwareIntegrationDB(t)
	applyDiscoveryTestSQL(t, db, "252_discovery_list_projection.sql", "253_discovery_queue_generations.sql", "254_discovery_address_links_and_reports.sql", "256_discovery_page_indexes.sql")
	run := func(query string, args ...any) {
		t.Helper()
		if _, e := db.Exec(query, args...); e != nil {
			t.Fatal(e)
		}
	}
	run(`ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_sync; ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_truncate;
 ALTER TABLE discovery_list_observation ENABLE TRIGGER discovery_address_fact;
 ALTER TABLE discovery_list_observation ENABLE TRIGGER discovery_address_fact_clear;
 ALTER TABLE discovery_identity_links ENABLE TRIGGER discovery_address_identity;
 ALTER TABLE discovery_identity_links ENABLE TRIGGER discovery_address_identity_clear;
 SELECT discovery_list_adopt(128),discovery_address_links_refresh(128)`)
	at := time.Now().UTC().Truncate(time.Second)
	put := func(key, mac, ip, domain string, n int) {
		run(`INSERT INTO discovery_observation_latest(id,device_key,origin,observed_at,valid_until,withdrawn,data)
 SELECT k,k,'arp',$5::timestamptz-interval '1 minute',$5::timestamptz+interval '1 hour',false,jsonb_build_object('id',k,'event_id',k,'source_id','capture','node','probe','site','campus','domain',$4::text,'vlan','2701/'||i,'origin','arp','mac',$2::text,'ip',$3::text,'observed_at',$5::timestamptz-interval '1 minute','valid_until',$5::timestamptz+interval '1 hour','confidence','confirmed')
 FROM (SELECT i,$1::text||i k FROM generate_series(1,$6::int) i) s`, key, mac, ip, domain, at, n)
	}
	run(`CREATE UNIQUE INDEX fixture_lookup ON discovery_observation_latest(device_key,source_id,origin,service_type,port)`)
	const mac = "c4:07:78:08:20:02"
	const ip = "222.204.69.254"
	put("dup", mac, ip, "a", 487)
	put("dual-stack", mac, "fe80::c607:78ff:fe08:2002", "a", 3)
	put("other-domain", mac, ip, "b", 1)
	put("other-mac", "c4:07:78:08:20:03", ip, "a", 1)
	put("local", "02:00:00:00:00:01", ip, "a", 2)
	run(`INSERT INTO endpoint_recognition_summary VALUES('mac:c4:07:78:08:20:02','desktop','Windows','{}',0.9,false,$1)`, at)
	for {
		var n int
		if e := db.QueryRow("SELECT discovery_list_refresh_groups(64)").Scan(&n); e != nil {
			t.Fatal(e)
		}
		if n == 0 {
			break
		}
	}
	run("ANALYZE discovery_list_observation;ANALYZE discovery_observation_latest;ANALYZE discovery_list_group_current")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", "list,statistics,coverage,address_links,ordered_pages,cross_vlan")
	r := Repository{DB: db, HardwareV2: true}
	q := DeviceQuery{Mode: "passive", IdentityScope: "devices", Window: 24 * time.Hour, SnapshotAt: at, Limit: 2}
	ctx := context.Background()
	check := func(q DeviceQuery, want int64) {
		t.Helper()
		m, e := r.DevicesIndexedMetadata(ctx, q)
		if e != nil || m.Total != want {
			t.Fatalf("filter %q/%q/%q total=%d want=%d err=%v", q.Search, q.DeviceType, q.IdentityScope, m.Total, want, e)
		}
	}
	check(q, 5)
	exact := q
	exact.Search = ip
	check(exact, 5)
	scoped := q
	scoped.IdentityScope = "scoped_devices"
	scoped.Search = mac
	check(scoped, 488)
	typed := q
	typed.DeviceType = "desktop"
	check(typed, 2)
	vlan := q
	vlan.VLAN = "2701/3"
	check(vlan, 1)
	for _, query := range []DeviceQuery{q, exact, typed} {
		seen := map[string]bool{}
		largest := 0
		for {
			page, e := r.DevicesIndexed(ctx, query)
			if e != nil {
				t.Fatal(e)
			}
			for _, v := range page["items"].([]DeviceView) {
				k := fmt.Sprint(v.Domain, "/", v.MAC, "/", v.VLAN)
				if seen[k] {
					t.Fatal("duplicate page member", k)
				}
				seen[k] = true
				if v.VLANScopeCount > largest {
					largest = v.VLANScopeCount
				}
			}
			if page["has_more"] != true {
				break
			}
			query.Cursor = page["next_cursor"].(string)
			if len(seen) > 6 {
				t.Fatal("unbounded pagination")
			}
		}
		want := 5
		if query.DeviceType != "" {
			want = 2
		}
		if len(seen) != want || largest != 487 {
			t.Fatalf("pagination %q/%q got %d, largest %d", query.Search, query.DeviceType, len(seen), largest)
		}
	}
	// A scoped correction takes effect in the same read transaction without
	// changing any raw identity. Both types remain available to the operator.
	run(`INSERT INTO passive_hardware_current(identity_key,scope_key,device_key,sensor_id,campus_id,access_domain,vlan,vrf,mac,hardware_type_status,hardware_type,first_seen,last_seen,active_until,data)
 SELECT f.base_identity,'test',f.device_key,f.sensor_id,f.site_id,f.access_domain,f.vlan,f.vrf,f.raw_mac,'identified',
 CASE WHEN f.vlan='2701/1' THEN 'printer' ELSE 'router' END,$1,$1,$1,'{}'::jsonb FROM discovery_list_observation f
 WHERE f.origin='arp' AND f.raw_ip='222.204.69.254' AND f.raw_mac=$2 AND f.access_domain='a' AND f.vlan IN ('2701/1','2701/2')`, at, mac)
	check(q, 491)
	run("DELETE FROM passive_hardware_current WHERE scope_key='test'")
	check(exact, 5)
	// With two distinct IPv4s for one scoped MAC its owner is ambiguous.
	put("alternate", mac, "192.0.2.2", "a", 1)
	check(exact, 6)
	run("UPDATE discovery_observation_latest SET withdrawn=true WHERE id='alternate1'")
	check(exact, 5)
	exported := exact
	exported.Export = true
	exported.Limit = 1000
	result, e := r.DevicesIndexed(ctx, exported)
	if e != nil || len(result["items"].([]DeviceView)) != 5 || result["has_more"] != false {
		t.Fatalf("export %v %v", result["has_more"], e)
	}
	pos, e := r.DevicesIndexedPosition(ctx, q, 2)
	if e != nil || pos.Cursor == "" {
		t.Fatalf("position %v %v", pos, e)
	}
	q.Cursor = pos.Cursor
	result, e = r.DevicesIndexed(ctx, q)
	if e != nil || len(result["items"].([]DeviceView)) != 2 {
		t.Fatalf("position page %v", e)
	}

}
