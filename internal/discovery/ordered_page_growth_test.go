package discovery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Standalone disposable socket database. This changes fixture rows and measures
// both index growth and corrections, so it must never run against a field DSN.
func TestOrderedDiscoveryPageGrowth(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_DISCOVERY_PAGE_GROWTH") != "1" {
		t.Skip("opt-in local PostgreSQL growth replay")
	}
	cfg, err := pgx.ParseConfig(os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil || len(cfg.Host) == 0 || cfg.Host[0] != '/' {
		t.Fatalf("a local PostgreSQL socket is required: %v", err)
	}
	db := hardwareIntegrationDB(t)
	applyDiscoveryTestSQL(t, db, "252_discovery_list_projection.sql", "253_discovery_queue_generations.sql", "254_discovery_address_links_and_reports.sql", "256_discovery_page_indexes.sql")
	run := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.Exec(statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	run(`CREATE UNIQUE INDEX growth_source_key ON discovery_observation_latest(device_key,source_id,origin,service_type,port);
 CREATE UNIQUE INDEX growth_recognition_key ON endpoint_recognition_summary(endpoint_id);
 CREATE INDEX growth_recognition_role ON endpoint_recognition_summary(role,last_seen DESC);
 CREATE UNIQUE INDEX growth_link_key ON discovery_identity_links(observation_id);
 CREATE INDEX growth_lease_key ON device_address_leases(event_id);
 ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_sync;
 ALTER TABLE discovery_observation_latest ENABLE TRIGGER discovery_list_truncate;
 ALTER TABLE discovery_list_observation ENABLE TRIGGER discovery_address_fact;
 ALTER TABLE discovery_list_observation ENABLE TRIGGER discovery_address_fact_clear;
 ALTER TABLE discovery_identity_links ENABLE TRIGGER discovery_address_identity;
 ALTER TABLE discovery_identity_links ENABLE TRIGGER discovery_address_identity_clear;
 SELECT discovery_list_adopt(100),discovery_address_links_refresh(100)`)
	at := time.Now().UTC().Truncate(time.Second)
	lower := 0
	for _, size := range []int{2048, 8192, 24576, 81920} {
		start := time.Now()
		run(`INSERT INTO discovery_observation_latest(id,device_key,origin,observed_at,valid_until,withdrawn,data)
   SELECT key,key,'arp',seen,$3::timestamptz+interval '1 day',false,jsonb_build_object('id',key,'event_id',key,'source_id','capture','node','probe','site','campus','domain','inside','vlan','10','origin','arp','mac',mac,'ip',ip,'observed_at',seen,'valid_until',$3::timestamptz+interval '1 day','confidence','confirmed')
   FROM (SELECT 'o-'||i key,CASE WHEN i%4=0 THEN '' ELSE '00:10:'||substr(hex,1,2)||':'||substr(hex,3,2)||':'||substr(hex,5,2)||':'||substr(hex,7,2) END mac,
    host('10.0.0.0'::inet+i) ip, $3::timestamptz-(i/3)*interval '1 second'-CASE WHEN i>24576 THEN interval '2 days' ELSE interval '0' END seen FROM (SELECT i,lpad(to_hex(i),8,'0') hex FROM generate_series($1::int+1,$2::int) i) g) d`, lower, size, at)
		elapsed := time.Since(start)
		run(`INSERT INTO discovery_identity_links SELECT 'o-'||i,'mac:'||f.raw_mac,'{}'
          FROM generate_series($1::int+1,$2::int) i JOIN discovery_list_observation f ON f.id='o-'||(i-1)
          WHERE i%16=0`, lower, size)
		for {
			var n int
			if err := db.QueryRow("SELECT discovery_address_links_refresh(250)").Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				break
			}
		}
		run(`INSERT INTO endpoint_recognition_summary SELECT 'mac:'||raw_mac,CASE WHEN substring(id FROM 3)::int%256=1 THEN 'printer' ELSE 'desktop' END,'','{}',0.85,false,$3::timestamptz
   FROM discovery_list_observation WHERE substring(id FROM 3)::int BETWEEN $1::int+1 AND $2::int AND substring(id FROM 3)::int%2=1`, lower, size, at)
		for {
			var n int
			if err := db.QueryRow("SELECT discovery_list_refresh_groups(64)").Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				break
			}
		}
		run(`ANALYZE discovery_observation_latest;ANALYZE discovery_list_observation;ANALYZE discovery_list_group_current;ANALYZE endpoint_recognition_summary;ANALYZE passive_hardware_current`)
		var bytes int64
		if err := db.QueryRow(`SELECT sum(pg_relation_size(c.oid)) FROM pg_class c WHERE c.relnamespace=current_schema()::regnamespace AND c.relname LIKE 'discovery_page_%' AND c.relkind='i'`).Scan(&bytes); err != nil {
			t.Fatal(err)
		}
		update := time.Now()
		run(`UPDATE discovery_observation_latest SET observed_at=observed_at+interval '1 millisecond'
   WHERE substring(id FROM 3)::int BETWEEN $1::int+1 AND $1::int+100`, lower)
		t.Logf("rows=%d inserted=%d insert_ms=%d correction_100_ms=%d new_index_bytes=%d", size, size-lower, elapsed.Milliseconds(), time.Since(update).Milliseconds(), bytes)
		measureOrderedGrowth(t, db, at, size)
		if size == 81920 {
			tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer tx.Rollback()
				for _, kind := range []string{"", "printer"} {
					t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", "list,address_links")
					compareOrderedPages(t, tx, DeviceQuery{HardwareV2: true, structured: true, Mode: "passive", Window: 24 * time.Hour, SnapshotAt: at, IdentityScope: "devices", Limit: 200, DeviceType: kind})
				}
			}()
		}
		lower = size
	}
}

func measureOrderedGrowth(t *testing.T, db *sql.DB, at time.Time, size int) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	repo := Repository{HardwareV2: true}
	q := DeviceQuery{Mode: "passive", Window: 24 * time.Hour, SnapshotAt: at, Limit: 20, IdentityScope: "devices"}
	firstCursor := ""
	for _, fixture := range []string{"first", "second", "printer", "common"} {
		if fixture == "second" {
			q.Cursor = firstCursor
		}
		if fixture == "printer" {
			q.Cursor = ""
			q.DeviceType = "printer"
		}
		if fixture == "common" {
			q.Cursor = ""
			q.DeviceType = "desktop"
		}
		var digest [32]byte
		for i, flags := range []string{"list,address_links", "list,address_links,ordered_pages"} {
			t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", flags)
			var durations []int64
			for repeat := 0; repeat < 5; repeat++ {
				start := time.Now()
				page, err := repo.devicesIndexed(ctx, tx, q, false)
				if err != nil {
					t.Fatal(err)
				}
				durations = append(durations, time.Since(start).Microseconds())
				encoded, err := json.Marshal(page)
				if err != nil {
					t.Fatal(err)
				}
				h := sha256.Sum256(encoded)
				if i == 0 && repeat == 0 {
					digest = h
				} else if digest != h {
					t.Fatalf("growth rows=%d case=%s digest %x != %x", size, fixture, digest, h)
				}
				if fixture == "first" {
					firstCursor = page["next_cursor"].(string)
				}
			}
			slices.Sort(durations)
			t.Logf("rows=%d case=%s ordered=%t n=5 median_us=%d max_us=%d digest=%x", size, fixture, i == 1, durations[2], durations[4], digest)
		}
	}
}
