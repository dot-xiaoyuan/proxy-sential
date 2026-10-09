package store

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"
)

func TestDeviceFactInventoryExcludesFutureObservations(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires owned isolated database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, `CREATE TABLE device_signal_facts(sensor_id text,signal_id text,ip inet,source text,kind text,value text,normalized_value text,strength text,confidence double precision,weight int,first_seen timestamptz,last_seen timestamptz,seen_count bigint,event_ids_sample jsonb)`)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		id, ip, sensor string
		at             time.Time
	}{
		{"current", "192.0.2.10", "s", end.Add(-time.Minute)},
		{"future-same-ip", "192.0.2.10", "s", end.Add(time.Minute)},
		{"future-only", "192.0.2.11", "s", end.Add(time.Hour)},
		{"expired", "192.0.2.12", "s", end.Add(-10*time.Minute - time.Microsecond)},
		{"lower-bound", "192.0.2.13", "s", end.Add(-10 * time.Minute)},
		{"upper-bound", "192.0.2.14", "s", end},
		{"other-sensor", "192.0.2.15", "other", end},
	}
	for i, c := range cases {
		mac := []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03", "aa:bb:cc:dd:ee:04", "aa:bb:cc:dd:ee:05", "aa:bb:cc:dd:ee:06", "aa:bb:cc:dd:ee:07"}[i]
		_, err = db.ExecContext(ctx, `INSERT INTO device_signal_facts VALUES($1,$2,$3::inet,'zeek','mac',$4,$4,'strong',0.9,30,$5,$5,1,'[]')`, c.sensor, c.id, c.ip, mac, c.at)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	items, err := (&PostgresStore{db: db}).buildDeviceInventoriesFromFacts(ctx, tx, "s", end.Format(time.RFC3339Nano), "10m", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("future/expired/sensor facts entered closed window: %+v", items)
	}
	for _, item := range items {
		if len(item.Signals) != 1 || len(item.Devices) != 1 {
			t.Fatalf("future fact invented extra candidates: %+v", item)
		}
		if item.IP != "192.0.2.10" && item.IP != "192.0.2.13" && item.IP != "192.0.2.14" {
			t.Fatalf("wrong window IP: %s", item.IP)
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM device_signal_facts`).Scan(&count); err != nil || count != 7 {
		t.Fatal("raw facts changed", count, err)
	}
}
