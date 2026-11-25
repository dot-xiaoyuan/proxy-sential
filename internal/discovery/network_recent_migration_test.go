package discovery

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestNetworkDeviceRecentPrebuildPostgres(t *testing.T) {
	db := discoveryTestSchema(t)
	const name = "discovery_latest_network_device_recent"
	const table = "discovery_observation_latest"
	const definition = "CREATE INDEX " + name + " ON " + table + " (observed_at DESC,id DESC)" +
		" WHERE coalesce(data->>'device_type','') IN ('router','gateway','access_point','switch','network_device')"
	body, err := os.ReadFile("../../migrations/postgres/257_discovery_latest_network_device_recent.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string) {
		t.Helper()
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	reject := func(message string) {
		t.Helper()
		if _, err := db.Exec(string(body)); err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("migration error = %v, want %q", err, message)
		}
	}
	exec("CREATE TABLE " + table + "(observed_at timestamptz, id text, data jsonb)")
	exec(string(body))
	exec("CREATE TABLE other_latest (LIKE " + table + ")")
	exec("DROP INDEX " + name)
	exec("INSERT INTO " + table + " VALUES(now(),'keep','{}')")
	reject("prebuild")
	for _, wrong := range []string{
		strings.Replace(definition, "id DESC", "id ASC", 1),
		strings.Replace(definition, "'router'", "'camera'", 1),
		strings.Replace(definition, " ON "+table, " ON other_latest", 1),
	} {
		exec(wrong)
		reject("mismatched")
		exec("DROP INDEX " + name)
	}

	// A concurrent build waiting for earlier writers has a catalog entry but
	// cannot yet serve reads. Simulate cancellation at that point.
	lock, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec("LOCK TABLE " + table + " IN ROW EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	concurrent := strings.Replace(definition, "CREATE INDEX ", "CREATE INDEX CONCURRENTLY ", 1)
	builder, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Close()
	if _, err := builder.ExecContext(context.Background(), "SET lock_timeout='100ms'"); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.ExecContext(context.Background(), concurrent); err == nil || !strings.Contains(err.Error(), "lock timeout") {
		t.Fatalf("build waiting for an earlier writer: %v", err)
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	reject("invalid")
	exec("DROP INDEX " + name)
	exec(concurrent)
	exec(string(body))
	exec(string(body))
}
