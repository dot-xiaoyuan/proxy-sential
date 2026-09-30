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
	endpointID, observationID := "passive-recognition-"+suffix, "passive-observation-"+suffix
	t.Cleanup(func() {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM discovery_identity_links WHERE observation_id=$1`, observationID)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM discovery_observations WHERE id=$1`, observationID)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM endpoint_recognition_summary WHERE endpoint_id=$1`, endpointID)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, endpointID)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, endpointID)
	})
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,attributes) VALUES($1,'00:11:22:33:44:55','endpoint',$2,$2,'{}')`, endpointID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$1,'passive:test','dns_sd',$2,$3,false,jsonb_build_object('name','Office Mac mini'))`, observationID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis) VALUES($1,$2,$3,'{}')`, observationID, endpointID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	hints, err := s.PassiveDiscoveryRecognitionHints(ctx, []string{endpointID}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(hints[endpointID]) != 1 || hints[endpointID][0].Value != "Office Mac mini" || hints[endpointID][0].ObservationID != observationID {
		t.Fatalf("unexpected passive hints: %+v", hints)
	}
	var generation int64
	if err = s.db.QueryRowContext(ctx, `SELECT dirty_generation FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, endpointID).Scan(&generation); err != nil || generation < 2 {
		t.Fatalf("discovery link did not enqueue recognition: generation=%d err=%v", generation, err)
	}
}
