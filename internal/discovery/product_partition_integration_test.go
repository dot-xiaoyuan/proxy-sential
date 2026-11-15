package discovery

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestSNMPProductPartitionsPostgresReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("product_partition_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	for _, file := range []string{"058_network_discovery.sql", "083_discovery_latest.sql", "248_discovery_product_partitions.sql"} {
		raw, err := os.ReadFile("../../migrations/postgres/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatal(file, err)
		}
	}
	now := time.Now().UTC()
	insert := func(id, partition string, at time.Time, withdrawn bool) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"latest_partition": partition, "event_id": id})
		_, err := db.Exec(`INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,'scoped-ip','snmp-source','snmp',$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, id, at, at.Add(time.Hour), withdrawn, string(raw))
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("legacy", "", now.Add(-time.Minute), false)
	insert("description", "snmp-fields:description", now, false)
	insert("oid", "snmp-fields:oid", now.Add(time.Second), false)
	insert("description", "snmp-fields:description", now, false)
	insert("late-description", "snmp-fields:description", now.Add(-time.Second), false)
	var count int
	if err = db.QueryRow("SELECT count(*) FROM discovery_observation_latest").Scan(&count); err != nil || count != 3 {
		t.Fatal("field loss or duplicate", count, err)
	}
	var id string
	if err = db.QueryRow("SELECT id FROM discovery_observation_latest WHERE service_type='snmp-fields:description'").Scan(&id); err != nil || id != "description" {
		t.Fatal("late event replaced description", id, err)
	}
	insert("withdraw-description", "snmp-fields:description", now.Add(2*time.Second), true)
	var withdrawn bool
	if err = db.QueryRow("SELECT withdrawn FROM discovery_observation_latest WHERE service_type='snmp-fields:description'").Scan(&withdrawn); err != nil || !withdrawn {
		t.Fatal("withdrawal lost", withdrawn, err)
	}
	if err = db.QueryRow("SELECT id FROM discovery_observation_latest WHERE service_type='snmp-fields:oid'").Scan(&id); err != nil || id != "oid" {
		t.Fatal("description withdrawal erased OID", id, err)
	}
}
