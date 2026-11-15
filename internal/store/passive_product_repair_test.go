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

func TestIPProductRepairPostgresRetryAndChangedSource(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not configured")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("product_repair_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	// No hardware tables: product refresh must not write physical facts.
	if _, err = db.Exec(`CREATE TABLE discovery_observation_latest(device_key text,source_id text,origin text,service_type text,port text,id text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,data jsonb,PRIMARY KEY(device_key,source_id,origin,service_type,port))`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROXY_SENTINEL_HARDWARE_V2", "true")
	for _, scenario := range []string{"normal", "source_changed", "rollback", "rules_changed"} {
		t.Run(scenario, func(t *testing.T) {
			if _, err = db.Exec("TRUNCATE discovery_observation_latest"); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			o := discovery.Observation{ID: "response", EventID: "response", SourceID: "zeek", Origin: "snmp", Node: "sensor", Site: "campus", Domain: "mirror", VLAN: "4005", IP: "10.0.0.4", ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute), Evidence: normalized.Event{EventID: "response", Payload: map[string]any{"is_response": true, "response_source_ip": "10.0.0.4", "system_object_id": "1.3.6.1.4.1.4881.1.1.10.1.186"}, RawRef: map[string]any{"content_sha256": "original-record"}}}
			raw, _ := json.Marshal(o)
			if _, err = db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,'snmp','','',$3,$4,$5,false,$6)`, o.Key(), o.SourceID, o.ID, o.ObservedAt, o.ValidUntil, string(raw)); err != nil {
				t.Fatal(err)
			}
			var stored []byte
			if err = db.QueryRow("SELECT data::text FROM discovery_observation_latest").Scan(&stored); err != nil {
				t.Fatal(err)
			}
			clue, err := discovery.BuildIPProductClue(o, now)
			if err != nil || clue == nil {
				t.Fatal(clue, err)
			}
			e := makeHardwareRepairEntry([5]string{o.Key(), o.SourceID, "snmp", "", ""}, stored, o)
			e.ProductRefreshVersion = clue.RuleVersion
			m := HardwareRepairManifest{SchemaVersion: HardwareRepairSchema, Window: HardwareRepairWindow{Sensor: o.Node, Origin: "snmp", From: now.Add(-time.Hour), Until: now}, SnapshotAt: now, Entries: []HardwareRepairEntry{e}}
			switch scenario {
			case "source_changed":
				_, err = db.Exec("UPDATE discovery_observation_latest SET data=jsonb_set(data,'{withdrawn}','true')")
			case "rollback":
				_, err = db.Exec("ALTER TABLE discovery_observation_latest ADD CONSTRAINT reject_annotation CHECK (NOT(data ? 'product_clue'))")
			case "rules_changed":
				m.Entries[0].ProductRefreshVersion = "different-catalog"
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := ApplyHardwareRepairBatch(context.Background(), db, m, 0, 1)
			if scenario == "rollback" || scenario == "rules_changed" {
				if err == nil {
					t.Fatal("failure escaped transaction/rule guard")
				}
				var unchanged bool
				if err = db.QueryRow("SELECT data=$1::jsonb FROM discovery_observation_latest", string(stored)).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("failed refresh changed evidence", err)
				}
				if scenario == "rollback" {
					if _, err = db.Exec("ALTER TABLE discovery_observation_latest DROP CONSTRAINT reject_annotation"); err != nil {
						t.Fatal(err)
					}
				}
				return
			}
			if err != nil || len(out) != 1 {
				t.Fatal(out, err)
			}
			if scenario == "source_changed" {
				if out[0].Status != "excluded" || out[0].Reason != "source_changed" {
					t.Fatal(out)
				}
				return
			}
			if out[0].Reason != "product_refreshed" || out[0].IdentityKey != "" {
				t.Fatal(out)
			}
			var unchanged bool
			if err = db.QueryRow("SELECT data-'product_clue'=$1::jsonb FROM discovery_observation_latest", string(stored)).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("product refresh changed source evidence", err)
			}
			out, err = ApplyHardwareRepairBatch(context.Background(), db, m, 0, 1)
			if err != nil || len(out) != 1 || out[0].Reason != "already_product_refreshed" {
				t.Fatal("uncertain commit retry not idempotent", out, err)
			}
		})
	}
}
