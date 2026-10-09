package controlplane

import (
	"context"
	"testing"
	"time"

	"proxy-sentinel/internal/legacy4k"
)

// The result/report segment is replayed; no upstream controller is contacted.
func TestSRunNativeResultObservationOrder(t *testing.T) {
	s, actor := srunIsolatedReplayServer(t)
	s.operations.doc = emptyOperationsDocument()
	s.reader = configuredProbeAudit{db: s.operations.db}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, actor)
	db := s.operations.db

	id := "observation-order-" + shortToken(12)
	if _, err := db.ExecContext(ctx, `INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,connector_type,action_mapping,encrypted_secret,mode,enabled,shadow_ready,updated_by) VALUES($1,'isolated','http://192.0.2.1:8001','srun4k','{}',''::bytea,'shadow',true,false,'isolated')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO srun4k_integrations(connector_id,host,source,sensor_id,reconcile_interval_hours,event_channel_state) VALUES($1,'192.0.2.1','srun4k:'||$1,'order',6,'healthy')`, id); err != nil {
		t.Fatal(err)
	}
	item, err := s.loadSRun4K(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	scoped := context.WithValue(ctx, srunOperationScopeKey{}, item)
	for _, tc := range []string{"old_failure_after_new_success", "old_test_success_after_new_failure", "old_sync_after_new_summary", "sync_summary_preserves_newer_health_failure", "newer_failure_is_applied", "same_operation_sync_failure_follows_probe", "newer_test_preserves_sync_summary", "missing_order_is_rejected", "clock_regression_with_newer_order", "missing_failure_order_is_rejected"} {
		t.Run(tc, func(t *testing.T) {
			order := int64(9)
			healthOrder, testOrder, syncOrder := int64(10), int64(10), int64(8)
			state, message := "healthy", ""
			switch tc {
			case "old_test_success_after_new_failure", "sync_summary_preserves_newer_health_failure":
				state, message = "failed", "newer check failed"
			case "old_sync_after_new_summary":
				syncOrder = 10
			case "newer_failure_is_applied":
				healthOrder, testOrder = 8, 8
			case "same_operation_sync_failure_follows_probe":
				healthOrder, testOrder = 9, 9
			case "newer_test_preserves_sync_summary", "clock_regression_with_newer_order":
				syncOrder = 10
				order = 11
			}
			if _, err := db.ExecContext(ctx, `UPDATE srun4k_integrations SET connection_state=$2,last_error=$3,last_tested_at=$4,last_synced_at=$5,identity_accounts=81,identity_sessions=81,products=6,groups_count=425,controls=3,last_health_result_order=$6,last_test_result_order=$7,last_sync_result_order=$8 WHERE connector_id=$1`, id, state, message, base.Add(2*time.Second), base.Add(time.Second), healthOrder, testOrder, syncOrder); err != nil {
				t.Fatal(err)
			}
			callCtx := context.WithValue(scoped, srunOperationOrderKey{}, order)
			if tc == "missing_order_is_rejected" || tc == "missing_failure_order_is_rejected" {
				callCtx = scoped
			}
			switch tc {
			case "old_failure_after_new_success", "newer_failure_is_applied", "same_operation_sync_failure_follows_probe", "missing_failure_order_is_rejected":
				action := "integration.srun4k.test"
				if tc == "same_operation_sync_failure_follows_probe" {
					action = "integration.srun4k.sync"
				}
				s.recordSRunOperationFailure(callCtx, id, "old or new isolated failure", action)
			case "old_sync_after_new_summary", "sync_summary_preserves_newer_health_failure":
				result, err := s.completeSRun4KSync(callCtx, item, legacy4k.InventoryStats{Accounts: 24, Sessions: 24, AddressRecords: 48}, 4, 2, 3, base.Add(3*time.Second))
				if tc == "old_sync_after_new_summary" {
					if err == nil || result != nil {
						t.Error("older sync overwrote newer summary")
					}
				} else {
					if err != nil || result["enforcement_ready"] != false || result["connection_state"] != "failed" {
						t.Errorf("sync cleared newer health failure or claimed readiness: %v %v", result, err)
					}
				}
			default:
				checked := base.Add(3 * time.Second)
				if tc == "clock_regression_with_newer_order" {
					checked = base
				}
				result, err := s.completeSRun4KTest(callCtx, item, 81, checked)
				if tc == "newer_test_preserves_sync_summary" || tc == "clock_regression_with_newer_order" {
					if err != nil || result == nil {
						t.Errorf("fresh check rejected: %v", err)
					}
				} else {
					if err == nil || result != nil {
						t.Error("obsolete or unordered test accepted")
					}
				}
			}
			after, err := s.loadSRun4K(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			expectedState := state
			if tc == "newer_failure_is_applied" || tc == "same_operation_sync_failure_follows_probe" {
				expectedState = "failed"
			}
			if after.ConnectionState != expectedState {
				t.Errorf("state=%s want %s", after.ConnectionState, expectedState)
			}
			expectedAccounts := 81
			if tc == "sync_summary_preserves_newer_health_failure" {
				expectedAccounts = 24
			}
			if after.IdentityAccounts != expectedAccounts {
				t.Errorf("summary accounts=%d want %d", after.IdentityAccounts, expectedAccounts)
			}
			if tc == "old_failure_after_new_success" && (!after.LastTestedAt.Equal(base.Add(2*time.Second)) || after.LastError != "") {
				t.Error("late failure changed latest check time/detail")
			}
		})
	}
}
