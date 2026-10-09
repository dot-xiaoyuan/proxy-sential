package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

func TestPolicyAuthorityNativeFailuresAreUnavailable(t *testing.T) {
	db := srunIsolatedReplayDB(t)
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, query := range []string{
		`CREATE FUNCTION pg_temp.policy_authority_failure() RETURNS integer LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-native-authority-detail'; END $$`,
		`CREATE TEMP TABLE enforcement_connectors(connector_id text,connector_type text,endpoint_url text,certificate_pem text)`,
		`CREATE TEMP TABLE enforcement_identity_sources(connector_id text,config_version bigint,public_config jsonb,encrypted_token bytea,state text,blocker text,observed_at timestamptz,last_success_at timestamptz,last_attempt_at timestamptz,record_count integer)`,
		`CREATE TEMP VIEW srun4k_integrations AS SELECT 'srun4k:one'::text source,'one'::text sensor_id,pg_temp.policy_authority_failure() reconcile_interval_hours`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{operations: &operationsState{db: db}}
	now := time.Now().UTC()
	reader := policySandboxReader{sessions: []policy.Session{{ID: "fixture", AccountID: "fixture", Source: "srun4k:one", SensorID: "one", ConfirmedAt: now}}}
	assertUnavailable := func(t *testing.T) {
		t.Helper()
		got, err := s.policySessions(ctx, reader, now)
		if err == nil || len(got) != 0 || strings.Contains(err.Error(), "private-native-authority-detail") {
			t.Fatalf("native authority failure hidden/leaked: rows=%d err=%v", len(got), err)
		}
		statuses, err := s.mergeManagedIdentitySources(ctx, []store.IdentitySourceStatus{{IdentityScope: store.IdentityScope{Source: "srun4k:one", SensorID: "one"}, ObservedAt: now, IntervalSeconds: 604800}}, now)
		if err == nil || len(statuses) != 0 || strings.Contains(err.Error(), "private-native-authority-detail") {
			t.Fatalf("native status failure hidden/leaked: rows=%d err=%v", len(statuses), err)
		}
	}
	t.Run("dynamic_registration", func(t *testing.T) { assertUnavailable(t) })
	if _, err := db.ExecContext(ctx, `DROP TABLE enforcement_identity_sources; INSERT INTO enforcement_connectors VALUES('owned','srun4k','',''); CREATE TEMP VIEW enforcement_identity_sources AS SELECT pg_temp.policy_authority_failure()::text connector_id,1::bigint config_version,'{}'::jsonb public_config,''::bytea encrypted_token,'healthy'::text state,''::text blocker,NULL::timestamptz observed_at,NULL::timestamptz last_success_at,NULL::timestamptz last_attempt_at,0::integer record_count`); err != nil {
		t.Fatal(err)
	}
	t.Run("managed_registration", func(t *testing.T) { assertUnavailable(t) })
}

func TestPolicyAuthorityNativeCancellationReturnsNoPartialResults(t *testing.T) {
	for _, operation := range []string{"policy", "status"} {
		t.Run(operation, func(t *testing.T) {
			db := srunIsolatedReplayDB(t)
			db.SetMaxOpenConns(1)
			setup, cancelSetup := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelSetup()
			for _, query := range []string{
				`CREATE FUNCTION pg_temp.policy_authority_wait() RETURNS integer LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(5); RETURN 6; END $$`,
				`CREATE TEMP TABLE enforcement_connectors(connector_id text,connector_type text,endpoint_url text,certificate_pem text)`,
				`CREATE TEMP TABLE enforcement_identity_sources(connector_id text,config_version bigint,public_config jsonb,encrypted_token bytea,state text,blocker text,observed_at timestamptz,last_success_at timestamptz,last_attempt_at timestamptz,record_count integer)`,
				`CREATE TEMP VIEW srun4k_integrations AS SELECT 'srun4k:one'::text source,'one'::text sensor_id,pg_temp.policy_authority_wait() reconcile_interval_hours`,
			} {
				if _, err := db.ExecContext(setup, query); err != nil {
					t.Fatal(err)
				}
			}
			s := &Server{operations: &operationsState{db: db}}
			now := time.Now().UTC()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			started := time.Now()
			var err error
			var count int
			if operation == "policy" {
				reader := policySandboxReader{sessions: []policy.Session{{ID: "fixture", Source: "srun4k:one", SensorID: "one", ConfirmedAt: now}}}
				rows, cause := s.policySessions(ctx, reader, now)
				count, err = len(rows), cause
			} else {
				rows, cause := s.mergeManagedIdentitySources(ctx, []store.IdentitySourceStatus{{IdentityScope: store.IdentityScope{Source: "srun4k:one", SensorID: "one"}, ObservedAt: now}}, now)
				count, err = len(rows), cause
			}
			if !errors.Is(err, context.DeadlineExceeded) || count != 0 || time.Since(started) > 3*time.Second {
				t.Fatalf("native timeout lost/continued: rows=%d elapsed=%s err=%v", count, time.Since(started), err)
			}
			t.Logf("native %s authority timeout retained, zero results, elapsed=%s", operation, time.Since(started))
		})
	}
}
