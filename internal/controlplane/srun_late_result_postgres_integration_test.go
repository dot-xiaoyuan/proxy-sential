package controlplane

import (
	"context"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/legacy4k"
)

// Exercise only result/report persistence, without fabricating successful
// upstream traffic or invoking any production controller.
func TestSRunHostChangeNativeLateResults(t *testing.T) {
	s, actor := srunIsolatedReplayServer(t)
	s.operations.doc = emptyOperationsDocument()
	s.reader = configuredProbeAudit{db: s.operations.db}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, actor)
	ctx = context.WithValue(ctx, srunOperationOrderKey{}, int64(1))
	var name string
	if err := s.operations.db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(name) {
		t.Fatal("dedicated acceptance database required")
	}
	id := "late-result-" + shortToken(12)
	if _, err := s.operations.db.ExecContext(ctx, `INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,connector_type,action_mapping,encrypted_secret,mode,enabled,shadow_ready,updated_by) VALUES($1,'isolated','http://192.0.2.2:8001','srun4k','{}',''::bytea,'shadow',true,false,'isolated-operator')`, id); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := srun4KIntegration{ConnectorID: id, Host: "192.0.2.1", Source: "srun4k:old", SensorID: "old", ReconcileIntervalHours: 6, EventChannelState: "healthy"}
	stats := legacy4k.InventoryStats{Accounts: 81, Sessions: 81, AddressRecords: 161}
	for _, tc := range []string{"previous_host_success", "previous_host_test_failure", "previous_host_sync_failure", "newer_sync", "current_event_state", "audit_rejected"} {
		t.Run(tc, func(t *testing.T) {
			db := s.operations.db
			if _, err := db.ExecContext(ctx, `DELETE FROM srun4k_integrations WHERE connector_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `DELETE FROM audit_logs WHERE target=$1`, id); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO srun4k_integrations(connector_id,host,source,sensor_id,event_channel_state,connection_state,reconcile_interval_hours) VALUES($1,'192.0.2.2','srun4k:new','new','waiting','pending',6)`, id); err != nil {
				t.Fatal(err)
			}
			current, err := s.loadSRun4K(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			submitted := item
			switch tc {
			case "newer_sync":
				submitted = current
				if _, err = db.ExecContext(ctx, `UPDATE srun4k_integrations SET last_synced_at=$2,last_sync_result_order=2 WHERE connector_id=$1`, id, now.Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			case "current_event_state", "audit_rejected":
				submitted = current
				submitted.EventChannelState = "healthy"
			}
			if tc == "audit_rejected" {
				if _, err = db.ExecContext(ctx, `CREATE FUNCTION reject_late_sync_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private fixture rejection'; END $$; CREATE TRIGGER reject_sync_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_late_sync_audit()`); err != nil {
					t.Fatal(err)
				}
				defer db.ExecContext(ctx, `DROP TRIGGER reject_sync_audit ON audit_logs`)
			}
			if tc == "previous_host_test_failure" || tc == "previous_host_sync_failure" {
				scoped := context.WithValue(ctx, srunOperationScopeKey{}, submitted)
				action := "integration.srun4k.test"
				if tc == "previous_host_sync_failure" {
					action = "integration.srun4k.sync"
				}
				s.recordSRunOperationFailure(scoped, id, "old host failed", action)
				var outcome string
				if err = db.QueryRowContext(ctx, `SELECT outcome FROM audit_logs WHERE target=$1 ORDER BY created_at DESC LIMIT 1`, id).Scan(&outcome); err != nil || outcome != "failed_for_previous_configuration" {
					t.Fatalf("late failure not traced separately: %s %v", outcome, err)
				}
			} else {
				result, err := s.completeSRun4KSync(ctx, submitted, stats, 4, 2, 3, now)
				if tc == "current_event_state" {
					if err != nil || result["event_channel_state"] != "waiting" || result["enforcement_ready"] != false {
						t.Fatalf("stale event status returned: %v %v", result, err)
					}
					return
				}
				if err == nil || result != nil {
					t.Fatalf("stale or unaudited sync accepted: %v %v", result, err)
				}
			}
			after, err := s.loadSRun4K(ctx, id)
			if err != nil || after.ConnectionState != "pending" || after.IdentityAccounts != 0 || after.IdentitySessions != 0 || after.LastTestedAt != nil {
				t.Fatalf("late result changed new host: %+v %v", after, err)
			}
			if tc == "newer_sync" {
				if after.LastSyncedAt == nil || !after.LastSyncedAt.Equal(now.Add(time.Hour)) {
					t.Fatal("newer sync overwritten")
				}
			} else if after.LastSyncedAt != nil {
				t.Fatal("rejected sync changed timestamp")
			}
		})
	}
}
