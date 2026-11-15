package discovery

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestCoverageAddressCountsPostgresScopeAndGateway(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	_, err = db.Exec(`CREATE TEMP TABLE discovery_observation_latest (origin text,observed_at timestamptz,withdrawn boolean,data jsonb)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	put := func(sensor, origin, ip, mac, vlan, status string, at time.Time) {
		t.Helper()
		_, e := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,false,jsonb_build_object('node',$3::text,'site','campus','domain','mirror','vlan',$4::text,'vrf','','ip',$5::text,'mac',$6::text,'evidence',jsonb_build_object('payload',jsonb_build_object('identity_status',$7::text))))`, origin, at, sensor, vlan, ip, mac, status)
		if e != nil {
			t.Fatal(e)
		}
	}
	put("campus-204", "arp", "10.1.1.1", "00:11:22:33:44:55", "10", "", now)
	put("campus-204", "arp", "10.1.1.2", "00:11:22:33:44:55", "10", "", now)
	put("campus-204", "arp", "10.1.1.1", "00:11:22:33:44:55", "20", "", now)
	put("campus-204", "dhcp", "10.1.2.1", "00:11:22:33:44:66", "10", "", now)
	put("campus-204", "http_device", "10.1.1.1", "00:aa:bb:cc:dd:ee", "10", "", now)
	put("campus-204", "sadp", "10.1.4.1", "00:aa:bb:cc:dd:ff", "10", "l2_mismatch", now)
	put("campus-204", "ndp", "fe80::1", "00:11:22:33:44:77", "10", "", now)
	put("other-sensor", "arp", "10.1.3.1", "00:11:22:33:44:88", "10", "", now)
	put("campus-204", "arp", "10.1.5.1", "00:11:22:33:44:99", "10", "", now.Add(-48*time.Hour))
	var got CoverageReport
	if err = coverageAddressCounts(context.Background(), db, "campus-204", now.Add(-24*time.Hour), now.Add(time.Second), &got); err != nil {
		t.Fatal(err)
	}
	if got.Subnet24 != 3 || got.IPv4 != 4 || got.IPv6 != 1 || got.MAC != 2 || got.IPMACPairs != 4 || got.ScopedMAC != 3 {
		t.Fatalf("cross-scope or gateway count: %+v", got)
	}
}
