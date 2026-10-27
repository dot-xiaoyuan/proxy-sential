package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestPassiveDiscoveryRecognitionHintsPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	suffix := fmt.Sprint(now.UnixNano())
	endpointID := "passive-recognition-" + suffix
	nameID := "passive-observation-name-" + suffix
	ssdpID := "passive-observation-ssdp-" + suffix
	snmpID := "passive-observation-snmp-" + suffix
	observations := []string{nameID, ssdpID, snmpID}
	t.Cleanup(func() {
		for _, id := range observations {
			_, _ = s.db.ExecContext(ctx, `DELETE FROM discovery_identity_links WHERE observation_id=$1`, id)
			_, _ = s.db.ExecContext(ctx, `DELETE FROM discovery_observations WHERE id=$1`, id)
		}
		_, _ = s.db.ExecContext(ctx, `DELETE FROM endpoint_recognition_summary WHERE endpoint_id=$1`, endpointID)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, endpointID)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, endpointID)
	})
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,attributes) VALUES($1,'00:11:22:33:44:55','endpoint',$2,$2,'{}')`, endpointID, now); err != nil {
		t.Fatal(err)
	}
	insert := func(id, origin string, observedAt time.Time, document string) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, `INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$1,'passive:test',$2,$3,$4,false,`+document+`)`, id, origin, observedAt, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis) VALUES($1,$2,$3,'{}')`, id, endpointID, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	insert(nameID, "dns_sd", now, `jsonb_build_object('name','Office Mac mini')`)
	insert(ssdpID, "ssdp", now.Add(-2*time.Second), `jsonb_build_object('model_name','Archer AX55','manufacturer','TP-Link')`)
	insert(snmpID, "snmp", now.Add(-4*time.Second), `jsonb_build_object('model_name','S5731-H48T4XC','evidence',jsonb_build_object('payload',jsonb_build_object('system_object_id','1.3.6.1.4.1.2011.2.23','system_description','Huawei Versatile Routing Platform Software')))`)

	hints, err := s.PassiveDiscoveryRecognitionHints(ctx, []string{endpointID}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	byField := map[string]DiscoveryRecognitionHint{}
	for _, hint := range hints[endpointID] {
		byField[hint.Field] = hint
	}
	if hint, ok := byField[""]; !ok || hint.Value != "Office Mac mini" || hint.ObservationID != nameID {
		t.Fatalf("hostname hint missing: %+v", hints)
	}
	for field, want := range map[string]string{
		"ssdp_model":        "Archer AX55",
		"ssdp_manufacturer": "TP-Link",
		"snmp_model":        "S5731-H48T4XC",
		"snmp_sysoid":       "1.3.6.1.4.1.2011.2.23",
		"snmp_sysdescr":     "Huawei Versatile Routing Platform Software",
		"mdns_model":        "",
	} {
		if want == "" {
			if _, ok := byField[field]; ok {
				t.Fatalf("%s must not be invented for an observation without that value: %+v", field, hints)
			}
			continue
		}
		if hint, ok := byField[field]; !ok || hint.Value != want {
			t.Fatalf("%s hint missing or wrong: %+v", field, hints)
		}
	}
	var generation int64
	if err = s.db.QueryRowContext(ctx, `SELECT dirty_generation FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, endpointID).Scan(&generation); err != nil || generation < 2 {
		t.Fatalf("discovery link did not enqueue recognition: generation=%d err=%v", generation, err)
	}
}
