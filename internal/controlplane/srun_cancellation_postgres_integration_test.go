package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Only result reporting is replayed in an isolated migrated database. No
// cancellation or failed upstream probe is injected into a live integration.
func TestSRunNativeCancellationPreservesCompleteIntegrationState(t *testing.T) {
	s, actor := srunIsolatedReplayServer(t)
	s.reader = configuredProbeAudit{db: s.operations.db}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, actor)
	db := s.operations.db
	id := "cancellation-" + shortToken(12)
	t.Cleanup(func() {
		for _, query := range []string{`DELETE FROM audit_logs WHERE target=$1`, `DELETE FROM srun4k_integrations WHERE connector_id=$1`, `DELETE FROM enforcement_connectors WHERE connector_id=$1`} {
			if _, err := db.ExecContext(context.Background(), query, id); err != nil {
				t.Errorf("owned cancellation fixture cleanup failed: %v", err)
			}
		}
	})
	if _, err := db.ExecContext(ctx, `INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,connector_type,action_mapping,encrypted_secret,mode,enabled,shadow_ready,updated_by) VALUES($1,'isolated','http://192.0.2.1:8001','srun4k','{}',''::bytea,'shadow',true,false,'isolated')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO srun4k_integrations(connector_id,host,source,sensor_id,reconcile_interval_hours,event_channel_state,connection_state,last_error,last_tested_at,last_synced_at,identity_accounts,identity_sessions,products,groups_count,controls,last_test_result_order,last_sync_result_order,last_health_result_order) VALUES($1,'192.0.2.1','srun4k:'||$1,'cancel',6,'waiting','healthy','','2026-10-01 03:00:00Z','2026-10-01 03:01:00Z',81,81,6,425,3,5,6,7)`, id); err != nil {
		t.Fatal(err)
	}
	item, err := s.loadSRun4K(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	parent := context.WithValue(context.WithValue(ctx, srunOperationScopeKey{}, item), srunOperationOrderKey{}, int64(100))
	cancelled, stop := context.WithCancel(parent)
	stop()
	for _, state := range []string{"healthy", "failed"} {
		for _, stage := range []string{"sync", "authorization_database", "redis", "catalog_redis", "northbound_api"} {
			t.Run(state+"/"+stage, func(t *testing.T) {
				message := ""
				if state == "failed" {
					message = "existing real upstream failure"
				}
				if _, err := db.ExecContext(ctx, `UPDATE srun4k_integrations SET connection_state=$2,last_error=$3 WHERE connector_id=$1`, id, state, message); err != nil {
					t.Fatal(err)
				}
				var before, after string
				if err := db.QueryRowContext(ctx, `SELECT row_to_json(s)::text FROM srun4k_integrations s WHERE connector_id=$1`, id).Scan(&before); err != nil {
					t.Fatal(err)
				}
				var auditBefore int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE target=$1`, id).Scan(&auditBefore); err != nil {
					t.Fatal(err)
				}
				auditExpected := 1
				cause := fmt.Errorf("isolated %s interrupted: %w", stage, context.Canceled)
				if stage == "sync" {
					s.recordSRunSyncFailure(cancelled, id, cause)
				} else {
					failure := s.recordSRunReadTestFailure(cancelled, id, "只读检查失败", stage+": isolated cancellation", cause)
					// A cancelled nested probe also ends its enclosing sync.
					s.recordSRunSyncFailure(cancelled, id, failure)
					auditExpected = 2
				}
				if err := db.QueryRowContext(ctx, `SELECT row_to_json(s)::text FROM srun4k_integrations s WHERE connector_id=$1`, id).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if before != after {
					t.Fatalf("cancel changed integration metadata:\nbefore=%s\nafter=%s", before, after)
				}
				var audits, cancelAudits int
				if err := db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE outcome='cancelled' AND actor=$2) FROM audit_logs WHERE target=$1`, id, actor.User.ID).Scan(&audits, &cancelAudits); err != nil {
					t.Fatal(err)
				}
				if audits-auditBefore != auditExpected || cancelAudits != audits {
					t.Fatalf("cancellation audit lost/misclassified: count=%d before=%d cancelled=%d", audits, auditBefore, cancelAudits)
				}
			})
		}
	}
	t.Run("timeout remains a health failure", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE srun4k_integrations SET connection_state='healthy',last_error='' WHERE connector_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		s.recordSRunReadTestFailure(cancelled, id, "只读检查超时", "redis: isolated deadline", context.DeadlineExceeded)
		var state, message string
		if err := db.QueryRowContext(ctx, `SELECT connection_state,last_error FROM srun4k_integrations WHERE connector_id=$1`, id).Scan(&state, &message); err != nil {
			t.Fatal(err)
		}
		if state != "failed" || message != "redis: isolated deadline" {
			t.Fatalf("real timeout suppressed: %s %s", state, message)
		}
	})
	t.Run("local CPU interruption preserves complete source state", func(t *testing.T) {
		for _, state := range []string{"healthy", "failed"} {
			for _, reason := range []string{"cancelled", "local_processing_timeout"} {
				t.Run(state+"/"+reason, func(t *testing.T) {
					if _, err := db.ExecContext(ctx, `UPDATE srun4k_integrations SET connection_state=$2,last_error=$3 WHERE connector_id=$1`, id, state, "existing source result"); err != nil {
						t.Fatal(err)
					}
					var before, after string
					if err := db.QueryRowContext(ctx, `SELECT row_to_json(s)::text FROM srun4k_integrations s WHERE connector_id=$1`, id).Scan(&before); err != nil {
						t.Fatal(err)
					}
					var count int
					if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE target=$1 AND outcome=$2 AND actor=$3`, id, reason, actor.User.ID).Scan(&count); err != nil {
						t.Fatal(err)
					}
					var local context.Context
					var stop context.CancelFunc
					cause := context.Canceled
					if reason == "cancelled" {
						local, stop = context.WithCancel(parent)
						stop()
					} else {
						local, stop = context.WithDeadline(parent, time.Now().Add(-time.Second))
						cause = context.DeadlineExceeded
					}
					defer stop()
					request := snapshotConversionFixture(2)
					partial, failure := prepareIdentitySnapshotContext(local, request, "local-replay", request.ObservedAt.Add(time.Minute), 200000)
					if len(partial.Events) != 0 || !errors.Is(failure, cause) {
						t.Fatal("local interrupted work exposed a partial inventory")
					}
					s.recordSRunSyncFailure(local, id, identityLocalWorkError(failure))
					if err := db.QueryRowContext(ctx, `SELECT row_to_json(s)::text FROM srun4k_integrations s WHERE connector_id=$1`, id).Scan(&after); err != nil {
						t.Fatal(err)
					}
					if before != after {
						t.Fatal("local interruption changed integration metadata")
					}
					var final int
					if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE target=$1 AND outcome=$2 AND actor=$3`, id, reason, actor.User.ID).Scan(&final); err != nil {
						t.Fatal(err)
					}
					if final != count+1 {
						t.Fatal("local interruption actor/outcome audit missing")
					}
				})
			}
		}
	})

}
