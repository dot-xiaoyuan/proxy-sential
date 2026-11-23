package discovery

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestMirrorFunnelCountsOnlyCurrentlyValidBindings(t *testing.T) {
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
	_, err = db.Exec(`CREATE TEMP TABLE passive_census_runtime (sensor_id text,last_source_at timestamptz,available_from timestamptz,last_success_at timestamptz,oldest_pending_at timestamptz);
CREATE TEMP TABLE passive_census_identifier_current (sensor_id text,scope_key text,kind text,value text,ip_family int,last_seen timestamptz);
CREATE TEMP TABLE passive_census_binding_current (scope_key text,ip text,mac text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,conflict boolean);
CREATE TEMP TABLE passive_hardware_current (identity_key text,scope_key text,mac text,sensor_id text,first_seen timestamptz,last_seen timestamptz,hardware_type text,hardware_type_status text)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	observed := now.Add(-time.Second)
	if _, err = db.Exec(`INSERT INTO passive_census_runtime VALUES('campus-204',$1,$2,$1,NULL)`, now, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	putID := func(kind, value string, family int) {
		t.Helper()
		if _, e := db.Exec(`INSERT INTO passive_census_identifier_current VALUES('campus-204','scope', $1,$2,$3,$4)`, kind, value, family, observed); e != nil {
			t.Fatal(e)
		}
	}
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"} {
		putID("ip", ip, 4)
	}
	for _, mac := range []string{"00:0c:29:00:00:01", "00:0c:29:00:00:02", "00:0c:29:00:00:03", "00:0c:29:00:00:04", "00:0c:29:00:00:05", "02:11:22:33:44:55"} {
		putID("mac", mac, 0)
	}
	for _, item := range []struct {
		ip, mac string
		until   time.Time
	}{
		{"10.0.0.1", "00:0c:29:00:00:01", now.Add(time.Hour)},
		{"10.0.0.1", "00:0c:29:00:00:02", now.Add(-time.Hour)},
		{"10.0.0.2", "00:0c:29:00:00:03", now.Add(-time.Hour)},
		{"10.0.0.2", "02:11:22:33:44:55", now.Add(time.Hour)},
		{"10.0.0.3", "00:0c:29:00:00:04", now.Add(time.Hour)},
		{"10.0.0.3", "00:0c:29:00:00:05", now.Add(time.Hour)},
		{"10.0.0.4", "00:0c:29:00:00:05", now.Add(-time.Hour)},
		{"10.0.0.5", "00:0c:29:00:00:05", now.Add(-time.Hour)},
	} {
		if _, err = db.Exec(`INSERT INTO passive_census_binding_current VALUES('scope',$1,$2,$3,$4,false,false)`, item.ip, item.mac, observed, item.until); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.Exec(`INSERT INTO passive_hardware_current VALUES('device-1','scope','00:0c:29:00:00:01','campus-204',$1,$1,'printer','identified'),('device-2','scope','02:11:22:33:44:55','campus-204',$1,$1,'camera','candidate')`, observed); err != nil {
		t.Fatal(err)
	}
	// The persisted conflict flag may remain set after a competing binding expires.
	// The current peer validity check must still admit the unambiguous pair.
	if _, err = db.Exec(`UPDATE passive_census_binding_current SET conflict=true WHERE ip='10.0.0.1' AND mac='00:0c:29:00:00:01'`); err != nil {
		t.Fatal(err)
	}
	// A valid competing binding can predate the report window.
	if _, err = db.Exec(`UPDATE passive_census_binding_current SET observed_at=$1 WHERE ip='10.0.0.3' AND mac='00:0c:29:00:00:05'`, now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE passive_census_binding_current SET withdrawn=true WHERE ip='10.0.0.5'`); err != nil {
		t.Fatal(err)
	}
	got, err := mirrorFunnelCounts(context.Background(), db, "campus-204", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got.IPv4Total != 6 || got.IPv4Only != 4 || got.MACTotal != 6 || got.MACOnly != 4 ||
		got.IPMACPairs != 2 || got.ScopedPairs != 2 || got.TrustedIdentities != 2 || got.IdentifiedPairs != 2 || got.TypedPairs != 1 || got.TypedIdentities != 1 {
		t.Fatalf("expired rebinding or candidate type counted as identified: %+v", got)
	}
	if *got.IPv4BindingFreshness != (CoverageBindingFreshness{Current: 2, Expired: 1, Uncertain: 2, NoBinding: 1}) {
		t.Fatalf("unexpected mirror address freshness: %+v", got.IPv4BindingFreshness)
	}
}
