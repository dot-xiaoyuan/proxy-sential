package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"proxy-sentinel/internal/evidence"
	"testing"
	"time"
)

func TestDeviceCenterCurrentAddressesPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TEMP TABLE device_address_leases(sensor_id text,campus_id text,ip inet,endpoint_id text,action text,valid_until timestamptz,observed_at timestamptz,event_id text);CREATE TEMP TABLE account_sessions(endpoint_id text,ip inet,started_at timestamptz,ended_at timestamptz,updated_at timestamptz);CREATE TEMP TABLE account_identity_session_projection(source text,sensor_id text,campus_id text,access_domain text,confirmed_at timestamptz,document jsonb);CREATE TEMP TABLE account_identity_projection_sources(source text,sensor_id text,campus_id text,access_domain text,observed_at timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i, r := range []struct {
		id, ip, action string
		until          time.Time
	}{{"dual", "2001:db8::8", "ack", now.Add(time.Hour)}, {"dual", "192.0.2.8", "ack", now.Add(time.Hour)}, {"expired", "192.0.2.9", "ack", now.Add(-time.Second)}, {"old", "192.0.2.10", "ack", now.Add(time.Hour)}, {"new", "192.0.2.10", "ack", now.Add(time.Hour)}, {"released", "192.0.2.11", "ack", now.Add(time.Hour)}, {"released", "192.0.2.11", "stop", now.Add(time.Hour)}, {"ipv6", "2001:db8::9", "ack", now.Add(time.Hour)}} {
		_, err = db.Exec(`INSERT INTO device_address_leases VALUES('a','campus',$1::inet,$2,$3,$4,$5,$6)`, r.ip, r.id, r.action, r.until, now.Add(time.Duration(i-20)*time.Second), string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
	}
	var b []byte
	err = db.QueryRowContext(context.Background(), deviceCenterAddressCTE+`SELECT jsonb_object_agg(endpoint_id,addresses) FROM current_addresses`).Scan(&b)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string][]string{}
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || len(m["dual"]) != 2 || m["dual"][0] != "192.0.2.8" || len(m["old"]) > 0 || len(m["released"]) > 0 || len(m["expired"]) > 0 {
		t.Fatalf("incorrect ownership/expiry: %s", b)
	}
}

func TestRouterDisplayAddressPriority(t *testing.T) {
	item := evidence.RouterAssessment{AssessmentID: "id", IP: "2001:db8::8", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), AuthBindings: []evidence.RouterAuthBinding{{AssignedIPs: []string{"192.0.2.8", "2001:db8::8"}}}}
	routerDisplayAddresses(&item)
	if item.PrimaryIP != "192.0.2.8" || len(item.CurrentAddresses) != 2 {
		t.Fatalf("%+v", item)
	}
	item.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339)
	routerDisplayAddresses(&item)
	if item.PrimaryIP != "" || len(item.CurrentAddresses) != 0 {
		t.Fatal("expired IP used as title")
	}
}
