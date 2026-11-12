package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func TestHardwareWorkerRequiresVerifiedInstalledCatalog(t *testing.T) {
	for _, status := range []string{"", "unavailable", "embedded_replay", "explicit_replay"} {
		if hardwareWorkerReadiness(fingerprint.HardwareResult{SourceStatus: status, Version: "test"}) == nil {
			t.Fatalf("worker accepted %q", status)
		}
	}
	if err := hardwareWorkerReadiness(fingerprint.HardwareResult{SourceStatus: "verified_bundle", Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if hardwareWorkerReadiness(fingerprint.HardwareResult{SourceStatus: "verified_bundle", Version: "test", Incomplete: true}) == nil {
		t.Fatal("worker accepted incomplete catalog")
	}
}

func TestHardwareOwnershipPostgresScopedLeaseRevocation(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("hardware_binding_%d", time.Now().UnixNano())
	if _, err = db.Exec(`CREATE SCHEMA ` + schema + `;SET search_path TO ` + schema + `;CREATE TABLE discovery_observations(id text PRIMARY KEY,origin text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,data jsonb)`); err != nil {
		t.Fatal(err)
	}
	defer func() { db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); db.Close() }()
	now := time.Now().UTC().Add(-time.Minute)
	binding := discovery.Observation{ID: "ack", Origin: "dhcp", Node: "sensor", Site: "campus", Domain: "access", VLAN: "20", VRF: "prod", IP: "10.0.0.2", MAC: "00:11:22:33:44:55", ObservedAt: now, ValidUntil: now.Add(time.Hour)}
	insert := func(o discovery.Observation) {
		raw, _ := json.Marshal(o)
		if _, err := db.Exec(`INSERT INTO discovery_observations VALUES($1,$2,$3,$4,$5,$6)`, o.ID, o.Origin, o.ObservedAt, o.ValidUntil, o.Withdrawn, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	insert(binding)
	response := binding
	response.Origin = "snmp"
	response.MAC = ""
	response.ObservedAt = now.Add(time.Second)
	response.Evidence = normalized.Event{Payload: map[string]any{"is_response": true, "response_source_ip": response.IP, "system_description": "H3C"}}
	got, err := resolveHardwareOwnership(context.Background(), db, response)
	if err != nil || got.MAC != binding.MAC {
		t.Fatalf("unique scoped ACK missing: %+v %v", got, err)
	}
	// Same IP on another VLAN never changes this endpoint's attribution.
	other := binding
	other.ID = "other-vlan"
	other.VLAN = "21"
	other.MAC = "00:aa:bb:cc:dd:ee"
	insert(other)
	got, err = resolveHardwareOwnership(context.Background(), db, response)
	if err != nil || got.MAC != binding.MAC {
		t.Fatalf("cross-VLAN collision: %+v %v", got, err)
	}
	// RELEASE suppresses the older ACK before its nominal lease time expires.
	release := binding
	release.ID = "release"
	release.Withdrawn = true
	release.ObservedAt = now.Add(2 * time.Second)
	release.ValidUntil = release.ObservedAt
	insert(release)
	response.ObservedAt = now.Add(3 * time.Second)
	got, err = resolveHardwareOwnership(context.Background(), db, response)
	if err != nil || got.MAC != "" {
		t.Fatalf("released lease still owns response: %+v %v", got, err)
	}
	// A replay before RELEASE still has its historical, event-time attribution.
	response.ObservedAt = now.Add(time.Second)
	got, err = resolveHardwareOwnership(context.Background(), db, response)
	if err != nil || got.MAC != binding.MAC {
		t.Fatalf("later RELEASE erased earlier attribution: %+v %v", got, err)
	}
	// A same-scope parallel ACK with another MAC is ambiguous, never latest-wins.
	other.ID = "other-mac"
	other.VLAN = "20"
	insert(other)
	got, err = resolveHardwareOwnership(context.Background(), db, response)
	if err != nil || got.MAC != "" {
		t.Fatalf("ambiguous lease chosen: %+v %v", got, err)
	}
	response.Evidence.Payload["endpoint_identity_unverified"] = true
	got, err = resolveHardwareOwnership(context.Background(), db, response)
	if err != nil || got.MAC != "" {
		t.Fatal("logical downstream device acquired gateway MAC")
	}
}

func TestHardwareBackfillPostgresDuplicateEventIDsAcrossPages(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("hardware_backfill_%d", time.Now().UnixNano())
	if _, err = db.Exec(`CREATE SCHEMA ` + schema + `;SET search_path TO ` + schema + `;CREATE TABLE discovery_observation_latest(device_key text,source_id text,origin text,service_type text,port text,id text,observed_at timestamptz,data jsonb,PRIMARY KEY(device_key,source_id,origin,service_type,port))`); err != nil {
		t.Fatal(err)
	}
	defer func() { db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); db.Close() }()
	for _, name := range []string{"241_passive_hardware_projection.sql", "242_passive_hardware_claim_index.sql", "243_passive_hardware_runtime.sql", "244_passive_hardware_backfill_gaps.sql"} {
		raw, err := os.ReadFile(filepath.Join("../../migrations/postgres", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 201; i++ {
		o := discovery.Observation{ID: "same-id", EventID: "same-id", SourceID: "source", Origin: "arp", Node: "sensor", Site: "campus", Domain: "access", VLAN: "20", MAC: fmt.Sprintf("00:11:22:00:%02x:%02x", i>>8, i&255), ObservedAt: now, ValidUntil: now.Add(time.Hour), Evidence: normalized.Event{RawRef: map[string]any{"test_fixture": "same-response"}}}
		if i == 200 {
			o.ObservedAt = now.Add(time.Hour)
		} // Concurrent replacement after the fixed bootstrap start.
		raw, _ := json.Marshal(o)
		if _, err = db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,'source','arp','','','same-id',$2,$3)`, fmt.Sprintf("key-%03d", i), o.ObservedAt, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	store := &DBStore{pg: &PostgresStore{db: db}}
	for i := 0; i < 3; i++ {
		if err = store.backfillPassiveHardwareLatest(context.Background(), "sensor"); err != nil {
			t.Fatal(err)
		}
	}
	var rows, changed, queued int
	var complete bool
	if err = db.QueryRow(`SELECT backfill_rows,backfill_changed_rows,backfill_complete FROM passive_hardware_runtime`).Scan(&rows, &changed, &complete); err != nil {
		t.Fatal(err)
	}
	db.QueryRow(`SELECT count(*) FROM passive_hardware_dirty`).Scan(&queued)
	if rows != 201 || changed != 1 || !complete || queued != 200 {
		t.Fatalf("duplicate IDs crossed cursor boundary: rows=%d changed=%d complete=%v queued=%d", rows, changed, complete, queued)
	}
}
