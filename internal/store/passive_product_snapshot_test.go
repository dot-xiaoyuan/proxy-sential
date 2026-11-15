package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func TestRetainedProductSnapshotProjectsWithoutRewritingEvidence(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("retained_product_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	for _, name := range []string{"058_network_discovery.sql", "083_discovery_latest.sql", "248_discovery_product_partitions.sql"} {
		raw, err := os.ReadFile("../../migrations/postgres/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	var now time.Time
	if err = db.QueryRow(`SELECT now()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	o := discovery.Observation{ID: "original-response", EventID: "original-response", SourceID: "zeek", Origin: "snmp", Node: "sensor", Site: "campus", Domain: "mirror", VLAN: "4005", IP: "10.0.0.4", ObservedAt: now.Add(-time.Hour), ValidUntil: now.Add(23 * time.Hour), Evidence: normalized.Event{EventID: "original-response", Payload: map[string]any{"is_response": true, "response_source_ip": "10.0.0.4", "system_description": "Ruijie 10G Ethernet Switch(S2910-24GT4XS-E) By Ruijie Networks"}, RawRef: map[string]any{"content_sha256": "original-raw-reference"}}}
	original, _ := json.Marshal(o)
	insert := func(v discovery.Observation) {
		t.Helper()
		raw, _ := json.Marshal(v)
		if _, err = db.Exec(`INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, v.ID, v.Key(), v.SourceID, v.Origin, v.ObservedAt, v.ValidUntil, v.Withdrawn, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	insert(o)
	newer := o
	newer.ID = "newer-oid"
	newer.EventID = newer.ID
	newer.ObservedAt = now.Add(-time.Minute)
	newer.Evidence = normalized.Event{EventID: newer.ID, Payload: map[string]any{"is_response": true, "response_source_ip": o.IP, "system_object_id": "1.3.6.1.4.1.4881.1.1.10.1.186"}}
	insert(newer)
	w := HardwareRepairWindow{Sensor: o.Node, Origin: "snmp", From: now.Add(-2 * time.Hour), Until: now}
	m, err := SnapshotProductResponses(context.Background(), db, w, []string{o.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = SnapshotProductResponses(context.Background(), db, w, []string{"not-retained"}); err == nil {
		t.Fatal("missing raw input concealed")
	}
	if _, err = ApplyHardwareRepairBatch(context.Background(), db, m, 0, 1); err == nil {
		t.Fatal("unprepared historical source accepted")
	}
	clue, err := discovery.BuildIPProductClue(o, now)
	if err != nil || clue == nil || clue.Type != "switch" {
		t.Fatal(clue, err)
	}
	m.Entries[0].ProductRefreshVersion = clue.RuleVersion
	// A trigger failure must roll back the derived history annotation too.
	if _, err = db.Exec(`ALTER TABLE discovery_observation_latest ADD CONSTRAINT reject_product CHECK (NOT(data ? 'product_clue'))`); err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyHardwareRepairBatch(context.Background(), db, m, 0, 1); err == nil {
		t.Fatal("trigger failure did not stop transaction")
	}
	var untouched bool
	if err = db.QueryRow(`SELECT data=$2::jsonb FROM discovery_observations WHERE id=$1`, o.ID, string(original)).Scan(&untouched); err != nil || !untouched {
		t.Fatal("trigger failure left a partial annotation", err)
	}
	if _, err = db.Exec(`ALTER TABLE discovery_observation_latest DROP CONSTRAINT reject_product`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		out, err := ApplyHardwareRepairBatch(context.Background(), db, m, 0, 1)
		if err != nil || out[0].Status != "admitted" {
			t.Fatal(out, err)
		}
	}
	var unchanged bool
	var n int
	if err = db.QueryRow(`SELECT data-'product_clue'-'latest_partition'=$2::jsonb FROM discovery_observations WHERE id=$1`, o.ID, string(original)).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("source evidence rewritten", err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM discovery_observation_latest`).Scan(&n); err != nil || n != 2 {
		t.Fatal("OID and description not preserved separately", n, err)
	}
	// A same-event correction must not be hidden behind an old product annotation.
	if _, err = db.Exec(`UPDATE discovery_observations SET data=jsonb_set(data,'{name}','"changed source"') WHERE id=$1`, o.ID); err != nil {
		t.Fatal(err)
	}
	out, err := ApplyHardwareRepairBatch(context.Background(), db, m, 0, 1)
	if err != nil || out[0].Reason != "source_changed" {
		t.Fatal("corrected source falsely reported idempotent", out, err)
	}
}
