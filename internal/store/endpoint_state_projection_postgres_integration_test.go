package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// Runs only with PROXY_SENTINEL_TEST_POSTGRES_DSN set. A long-online member that exists only in the
// snapshot projection gets its current IP and account on the terminal row, and loses them once its
// scope's snapshot is no longer current.
func TestPostgresEndpointStateUsesSnapshotProjection(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	suffix := time.Now().UnixNano()
	source := fmt.Sprintf("projection-test-%d", suffix)
	endpoint := fmt.Sprintf("mac:02:%02x:00:00:00:01", suffix%256)
	cleanup := func() {
		for _, q := range []string{
			`DELETE FROM account_identity_session_projection WHERE source=$1`,
			`DELETE FROM account_identity_projection_sources WHERE source=$1`,
		} {
			pg.db.ExecContext(context.Background(), q, source)
		}
		for _, q := range []string{`DELETE FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, `DELETE FROM endpoint_inventory_accounts WHERE endpoint_id=$1`, `DELETE FROM endpoint_entities WHERE endpoint_id=$1`} {
			pg.db.ExecContext(context.Background(), q, endpoint)
		}
	}
	cleanup()
	defer cleanup()
	longAgo := time.Now().UTC().Add(-19 * 24 * time.Hour)
	if _, err = pg.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen) VALUES($1,$2,'endpoint',$3,$3)`, endpoint, endpoint[4:], longAgo); err != nil {
		t.Fatal(err)
	}
	document := fmt.Sprintf(`{"session_id":"s","account_id":"acct-p","endpoint_id":%q,"ip":"10.157.2.191","reconcile_interval_seconds":1800,"vlan":"26150014","nas_ip":"222.204.1.189"}`, endpoint)
	if _, err = pg.db.ExecContext(ctx, `INSERT INTO account_identity_session_projection(source,sensor_id,campus_id,access_domain,session_id,ip,account_id,confirmed_at,document) VALUES($1,'sensor','campus','domain','s','10.157.2.191','acct-p',$2,$3::jsonb)`, source, longAgo, document); err != nil {
		t.Fatal(err)
	}
	setSnapshot := func(at time.Time) {
		t.Helper()
		if _, err := pg.db.ExecContext(ctx, `INSERT INTO account_identity_projection_sources VALUES($1,'sensor','campus','domain',$2) ON CONFLICT(source,sensor_id,campus_id,access_domain) DO UPDATE SET observed_at=EXCLUDED.observed_at`, source, at); err != nil {
			t.Fatal(err)
		}
	}
	current := func() (ip string, accounts int) {
		t.Helper()
		if err := pg.refreshEndpointStates(ctx, []string{endpoint}); err != nil {
			t.Fatal(err)
		}
		if err := pg.db.QueryRowContext(ctx, `SELECT COALESCE(host(current_ip),''),(SELECT count(*) FROM endpoint_inventory_accounts WHERE endpoint_id=$1) FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, endpoint).Scan(&ip, &accounts); err != nil {
			t.Fatal(err)
		}
		return ip, accounts
	}
	setSnapshot(time.Now().UTC().Add(-10 * time.Minute))
	if ip, accounts := current(); ip != "10.157.2.191" || accounts != 1 {
		t.Fatalf("current snapshot member not shown: ip=%q accounts=%d", ip, accounts)
	}
	setSnapshot(time.Now().UTC().Add(-2 * time.Hour))
	if ip, accounts := current(); ip != "" || accounts != 0 {
		t.Fatalf("stale snapshot member still shown: ip=%q accounts=%d", ip, accounts)
	}
}
