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
	_, err = db.Exec(`CREATE TEMP TABLE discovery_observation_latest (origin text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,data jsonb)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	put := func(sensor, origin, ip, mac, vlan, status string, at, validUntil time.Time) {
		t.Helper()
		_, e := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,$8,false,jsonb_build_object('node',$3::text,'site','campus','domain','mirror','vlan',$4::text,'vrf','','ip',$5::text,'mac',$6::text,'confidence','confirmed','evidence',jsonb_build_object('payload',jsonb_build_object('identity_status',$7::text))))`, origin, at, sensor, vlan, ip, mac, status, validUntil)
		if e != nil {
			t.Fatal(e)
		}
	}
	active := now.Add(time.Hour)
	put("campus-204", "arp", "10.1.1.1", "00:11:22:33:44:55", "10", "", now, active)
	put("campus-204", "arp", "10.1.1.2", "00:11:22:33:44:55", "10", "", now, active)
	put("campus-204", "arp", "10.1.1.1", "00:11:22:33:44:55", "20", "", now, now.Add(-time.Minute))
	put("campus-204", "dhcp", "10.1.2.1", "00:11:22:33:44:66", "10", "", now, active)
	put("campus-204", "http_device", "10.1.1.1", "00:aa:bb:cc:dd:ee", "10", "", now, active)
	put("campus-204", "sadp", "10.1.4.1", "00:aa:bb:cc:dd:ff", "10", "l2_mismatch", now, active)
	put("campus-204", "ndp", "fe80::1", "00:11:22:33:44:77", "10", "", now, active)
	put("other-sensor", "arp", "10.1.3.1", "00:11:22:33:44:88", "10", "", now, active)
	put("campus-204", "arp", "10.1.5.1", "00:11:22:33:44:99", "10", "", now.Add(-48*time.Hour), active)
	put("campus-204", "arp", "10.1.1.1", "00:11:22:33:44:66", "", "", now, active)
	var got CoverageReport
	if err = coverageAddressCounts(context.Background(), db, "campus-204", now.Add(-24*time.Hour), now.Add(time.Second), &got); err != nil {
		t.Fatal(err)
	}
	if got.Subnet24 != 3 || got.IPv4 != 4 || got.IPv6 != 1 || got.MAC != 2 || got.IPMACPairs != 5 || got.ScopedMAC != 4 ||
		got.IPv4WithMAC != 3 || got.IPMACUniquePairs != 4 || got.IPMACValidScopedPairs != 4 ||
		got.MultiMACIPv4 != 1 || got.MultiScopeIPMACPairs != 1 || got.BlankAndFilledVLANPairs != 0 {
		t.Fatalf("cross-scope or gateway count: %+v", got)
	}
	past := now.Add(-time.Hour)
	put("campus-204", "arp", "10.1.1.3", "00:11:22:33:44:55", "10", "", past, now)
	put("campus-204", "ndp", "fe80::2", "00:11:22:33:44:55", "10", "", past, now)
	put("campus-204", "arp", "10.1.1.4", "00:11:22:33:44:55", "10", "", now, active)
	put("campus-204", "arp", "10.1.1.4", "00:11:22:33:44:66", "10", "", now, active)
	put("campus-204", "arp", "10.1.1.5", "00:11:22:33:44:55", "10", "", now, active)
	if _, err = db.Exec(`INSERT INTO discovery_observation_latest
SELECT 'dhcp',$1::timestamptz,$1::timestamptz,true,data FROM discovery_observation_latest WHERE data->>'ip'='10.1.1.5'`, now); err != nil {
		t.Fatal(err)
	}
	if err = coverageAddressCounts(context.Background(), db, "campus-204", now.Add(-24*time.Hour), now.Add(time.Second), &got); err != nil {
		t.Fatal(err)
	}
	if *got.IPv4BindingFreshness != (CoverageBindingFreshness{Current: 3, Expired: 1, Uncertain: 2, NoBinding: 1}) ||
		*got.IPv6BindingFreshness != (CoverageBindingFreshness{Current: 1, Expired: 1}) {
		t.Fatalf("unexpected address freshness: IPv4 %+v, IPv6 %+v", got.IPv4BindingFreshness, got.IPv6BindingFreshness)
	}
}

func TestCoverageEvidenceCountsPostgresFeatureAndIdentityBoundary(t *testing.T) {
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
	_, err = db.Exec(`CREATE TEMP TABLE discovery_observation_latest (device_key text,origin text,observed_at timestamptz,withdrawn boolean,data jsonb);
CREATE TEMP TABLE passive_hardware_current (device_key text,sensor_id text,last_seen timestamptz,hardware_type_status text,hardware_type text,active_until timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	put := func(ip, key, origin string) {
		t.Helper()
		if _, e := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,$3,false,jsonb_build_object('node','campus-204','ip',$4::text))`, key, origin, now, ip); e != nil {
			t.Fatal(e)
		}
	}
	bind := func(key, status, hardwareType string) {
		t.Helper()
		if _, e := db.Exec(`INSERT INTO passive_hardware_current VALUES($1,'campus-204',$2,$3,$4,$5)`, key, now, status, hardwareType, now.Add(-time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	put("10.2.0.1", "one", "arp")
	put("10.2.0.2", "two", "dhcp")
	put("10.2.0.3", "three", "http_device")
	put("10.2.0.4", "four", "sadp")
	put("10.2.0.5", "five", "arp")
	put("10.2.0.6", "six", "sip")
	put("10.2.0.7", "seven", "arp")
	put("10.2.0.8", "eight", "arp")
	put("10.2.0.4", "seven", "arp")
	bind("one", "revoked", "")
	bind("two", "candidate", "")
	bind("three", "candidate", "")
	bind("four", "identified", "printer")
	bind("seven", "revoked", "router")
	bind("eight", "conflict", "")
	var got CoverageReport
	if err = coverageEvidenceCounts(context.Background(), db, "campus-204", now.Add(-time.Hour), now.Add(time.Second), &got); err != nil {
		t.Fatal(err)
	}
	if got.TypedIPv4 != 1 || got.IdentityNoTypeIPv4 != 5 || got.NoIdentityIPv4 != 2 ||
		got.UntypedNetworkOnlyIPv4 != 3 || got.UntypedDHCPOnlyIPv4 != 1 ||
		got.UntypedApplicationIPv4 != 1 || got.UntypedOtherIPv4 != 0 || got.RevokedTypeIPv4 != 2 || got.DiagnosticAsOf == nil {
		t.Fatalf("unexpected evidence buckets: %+v", got)
	}
	if got.IPv4TypeReview == nil || *got.IPv4TypeReview != (CoverageIPv4TypeReview{WithdrawnConfirmation: 1, Conflict: 1, ConfirmedInactive: 1}) {
		t.Fatalf("unexpected type review: %+v", got.IPv4TypeReview)
	}
}
