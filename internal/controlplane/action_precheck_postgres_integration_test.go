package controlplane

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestActionPrecheckNativeSlowChannelUsesCallerDeadline(t *testing.T) {
	for _, stage := range []string{"precheck", "native_final_guard"} {
		t.Run(stage, func(t *testing.T) {
			db := srunIsolatedReplayDB(t)
			db.SetMaxOpenConns(1)
			setup, cancelSetup := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelSetup()
			for _, query := range []string{
				`CREATE FUNCTION pg_temp.slow_event_channel() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN true; END $$`,
				`CREATE TEMP TABLE enforcement_connectors(connector_id text,connector_type text)`,
				`INSERT INTO enforcement_connectors VALUES('owned','srun4k')`,
				`CREATE TEMP VIEW srun4k_integrations AS SELECT 'owned'::text connector_id,'scope'::text source,'sensor'::text sensor_id`,
				`CREATE TEMP VIEW identity_pipeline_scopes AS SELECT 'scope'::text source,'sensor'::text sensor_id,'ncu'::text campus_id,'campus-auth'::text access_domain,pg_temp.slow_event_channel() enabled,0::bigint accepted_sequence,0::bigint processed_sequence,0::bigint pending_records,''::text last_error,now() heartbeat_at,'completed'::text calibration_state,now() snapshot_at`,
				`CREATE TEMP VIEW identity_bridge_runtime AS SELECT 'ncu-legacy-4k'::text bridge_id,now() heartbeat_at,now() queue_sampled_at,false queue_sample_error,'healthy'::text event_channel_state,'healthy'::text online_channel_state,'healthy'::text snapshot_state,0 source_queue,0 processing_queue,0 quarantine_queue,1 active_config_version,'192.0.2.1'::text active_host`,
				`CREATE TEMP VIEW identity_bridge_configs AS SELECT 'ncu-legacy-4k'::text bridge_id,1 config_version,'192.0.2.1'::text desired_host`,
			} {
				if _, err := db.ExecContext(setup, query); err != nil {
					t.Fatal(err)
				}
			}
			a := EnforcementAction{ActionID: "owned-action", ConnectorID: "owned", ActionType: "release", Status: "running", Mode: "active"}
			doc := emptyOperationsDocument()
			doc.Actions[a.ActionID] = a
			doc.Connectors[a.ConnectorID] = ActionConnector{ConnectorID: a.ConnectorID, ConnectorType: "srun4k", Mode: "active", Enabled: true}
			s := &Server{operations: &operationsState{db: db, doc: doc}}
			if stage == "native_final_guard" {
				s.operations.readView = true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			started := time.Now()
			var err error
			native := &nativeQueueSandbox{}
			if stage == "precheck" {
				err = s.validatePolicyDeliveryContext(ctx, a)
			} else {
				err = native.RequestDisconnectChecked(ctx, "fixture", "fixture", "radius", func(guard context.Context) error { return s.nativeAuthorization(guard, a) })
			}
			elapsed := time.Since(started)
			if !errors.Is(err, context.DeadlineExceeded) || native.calls.Load() != 0 || elapsed > 350*time.Millisecond {
				t.Fatalf("caller deadline lost: elapsed=%s guarded_callbacks=%d err=%v", elapsed, native.calls.Load(), err)
			}
			t.Logf("native %s: deadline retained, guarded_callbacks=0, elapsed=%s", stage, elapsed)
		})
	}
}

func TestActionPrecheckNativeAdmissionAvoidsGlobalLockAndReadsStop(t *testing.T) {
	s, _ := srunIsolatedReplayServer(t)
	ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ops.db.Close() })
	s.operations = ops
	id := "precheck-admission-" + shortToken(12)
	a := EnforcementAction{ActionID: id, IdempotencyKey: id, ConnectorID: id, ActionType: "release", Status: "running", Mode: "active", CreatedAt: formatDBTime(time.Now().UTC()), UpdatedAt: formatDBTime(time.Now().UTC())}
	s.operations.mu.Lock()
	s.operations.doc.Actions[id] = a
	s.operations.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "isolated guard", EndpointURL: "http://127.0.0.1:1/must-not-send", Enabled: true, Mode: "active", ShadowReady: true, UpdatedAt: a.UpdatedAt}
	err = s.operations.saveLocked()
	s.operations.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lock, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations'))`); err != nil {
		t.Fatal(err)
	}
	s.operations.mu.Mutex.Lock()
	defer s.operations.mu.Mutex.Unlock()
	if err := s.nativeAuthorization(ctx, a); err != nil {
		t.Fatalf("unrelated global lock blocked current SQL guard: %v", err)
	}
	if _, err = s.operations.db.ExecContext(ctx, `INSERT INTO control_plane_settings(setting_key,setting_value,updated_at) VALUES('global_emergency_stop','true',now()) ON CONFLICT(setting_key) DO UPDATE SET setting_value='true'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.operations.db.ExecContext(context.Background(), `UPDATE control_plane_settings SET setting_value='false' WHERE setting_key='global_emergency_stop'`); err != nil {
			t.Error(err)
		}
	})
	if err := s.nativeAuthorization(ctx, a); err == nil {
		t.Fatal("guard trusted stale false emergency-stop cache")
	}
	if s.operations.doc.GlobalStop {
		t.Fatal("fixture did not retain stale in-memory state")
	}
}

func TestIdentityAdmissionChecksLiveProgressAndSource(t *testing.T) {
	db := srunIsolatedReplayDB(t)
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	for _, q := range []string{
		`CREATE TEMP TABLE srun4k_integrations(connector_id text,source text,sensor_id text)`,
		`INSERT INTO srun4k_integrations VALUES('owned','scope','sensor')`,
		`CREATE TEMP TABLE identity_pipeline_scopes AS SELECT 'scope'::text source,'sensor'::text sensor_id,'ncu'::text campus_id,'campus-auth'::text access_domain,true enabled,10::bigint accepted_sequence,10::bigint processed_sequence,0::bigint pending_records,''::text last_error,now() heartbeat_at,'completed'::text calibration_state,now() snapshot_at`,
		`CREATE TEMP TABLE identity_bridge_runtime AS SELECT 'ncu-legacy-4k'::text bridge_id,now() heartbeat_at,now() queue_sampled_at,false queue_sample_error,'healthy'::text event_channel_state,'healthy'::text online_channel_state,'healthy'::text snapshot_state,0 source_queue,0 processing_queue,0 quarantine_queue,1 active_config_version,'192.0.2.1'::text active_host`,
		`CREATE TEMP TABLE identity_bridge_configs AS SELECT 'ncu-legacy-4k'::text bridge_id,1 config_version,'192.0.2.1'::text desired_host`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{operations: &operationsState{db: db}}
	if healthy, err := s.srunEventChannelStatusContext(ctx, "owned"); err != nil || !healthy {
		t.Fatalf("valid checkpoint denied: %v %v", healthy, err)
	}
	for _, tc := range []struct{ name, change, undo string }{
		{"accepted_not_processed", `UPDATE identity_pipeline_scopes SET accepted_sequence=11,pending_records=1`, `UPDATE identity_pipeline_scopes SET accepted_sequence=10,pending_records=0`},
		{"worker_stale", `UPDATE identity_pipeline_scopes SET heartbeat_at=now()-interval '16 seconds'`, `UPDATE identity_pipeline_scopes SET heartbeat_at=now()`},
		{"identity_failed", `UPDATE identity_pipeline_scopes SET last_error='failed'`, `UPDATE identity_pipeline_scopes SET last_error=''`},
		{"snapshot_building", `UPDATE identity_pipeline_scopes SET calibration_state='building'`, `UPDATE identity_pipeline_scopes SET calibration_state='completed'`},
		{"source_switch", `UPDATE identity_bridge_configs SET config_version=2`, `UPDATE identity_bridge_configs SET config_version=1`},
		{"queue_sampling_failed", `UPDATE identity_bridge_runtime SET queue_sample_error=true`, `UPDATE identity_bridge_runtime SET queue_sample_error=false`},
		{"bridge_stale", `UPDATE identity_bridge_runtime SET heartbeat_at=now()-interval '16 seconds'`, `UPDATE identity_bridge_runtime SET heartbeat_at=now()`},
		{"quarantine", `UPDATE identity_bridge_runtime SET quarantine_queue=1`, `UPDATE identity_bridge_runtime SET quarantine_queue=0`},
		{"processing", `UPDATE identity_bridge_runtime SET processing_queue=1`, `UPDATE identity_bridge_runtime SET processing_queue=0`},
		{"wrong_scope", `UPDATE identity_pipeline_scopes SET campus_id='another-campus'`, `UPDATE identity_pipeline_scopes SET campus_id='ncu'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, tc.change); err != nil {
				t.Fatal(err)
			}
			healthy, err := s.srunEventChannelStatusContext(ctx, "owned")
			if err != nil || healthy {
				t.Fatalf("unsafe admission: %v %v", healthy, err)
			}
			if _, err = db.ExecContext(ctx, tc.undo); err != nil {
				t.Fatal(err)
			}
		})
	}
}
