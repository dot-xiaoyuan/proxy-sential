package discovery

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The overlap must use exactly the device and mirror address sets that feed
// ipv4 and mirror_funnel.ipv4_total, so the report can state their union.
func TestCoverageMirrorOverlapMatchesBothReportedAddressSets(t *testing.T) {
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
	if _, err = db.Exec(`CREATE TEMP TABLE discovery_observation_latest (device_key text,observed_at timestamptz,withdrawn boolean,data jsonb);
CREATE TEMP TABLE passive_census_identifier_current (sensor_id text,scope_key text,kind text,value text,ip_family int,last_seen timestamptz)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	from, until := now.Add(-24*time.Hour), now
	mirrorUntil := now.Add(-2 * time.Minute)
	mirrorFrom := mirrorUntil.Add(-24 * time.Hour)
	device := func(key, node, ip string, at time.Time, withdrawn bool) {
		t.Helper()
		if _, e := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,$3,jsonb_build_object('node',$4::text,'ip',$5::text))`, key, at, withdrawn, node, ip); e != nil {
			t.Fatal(e)
		}
	}
	mirror := func(scope, kind, value string, family int, at time.Time) {
		t.Helper()
		if _, e := db.Exec(`INSERT INTO passive_census_identifier_current VALUES('campus-204',$1,$2,$3,$4,$5)`, scope, kind, value, family, at); e != nil {
			t.Fatal(e)
		}
	}
	recent := now.Add(-time.Hour)
	device("d1", "campus-204", "10.0.0.1", recent, false)
	device("d1b", "campus-204", "10.0.0.1", recent, false)                // same address, second identity
	device("d2", "campus-204", "10.0.0.2", recent, true)                  // withdrawn
	device("d3", "campus-204", "10.0.0.3", now.Add(-25*time.Hour), false) // outside device window
	device("d4", "campus-other", "10.0.0.4", recent, false)               // other sensor
	device("d5", "campus-204", "fe80::1", recent, false)                  // IPv6
	device("d6", "campus-204", "10.0.0.6", recent, false)
	device("d7", "campus-204", "10.0.0.7", recent, false)
	mirror("scope-a", "ip", "10.0.0.1", 4, recent)
	mirror("scope-b", "ip", "10.0.0.1", 4, recent) // same address in another scope
	mirror("scope-a", "ip", "10.0.0.2", 4, recent)
	mirror("scope-a", "ip", "10.0.0.3", 4, recent)
	mirror("scope-a", "ip", "10.0.0.4", 4, recent)
	mirror("scope-a", "ip", "fe80::1", 6, recent)
	mirror("scope-a", "ip", "10.0.0.6", 4, now.Add(-26*time.Hour)) // outside mirror window
	mirror("scope-a", "mac", "10.0.0.7", 0, recent)                // not an IP identifier
	mirror("scope-a", "ip", "10.0.0.9", 4, recent)                 // mirror only
	got, err := coverageMirrorOverlap(context.Background(), db, "campus-204", from, until, mirrorFrom, mirrorUntil)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("overlap = %d, want 1 (only 10.0.0.1 is in both report sets)", got)
	}
}
