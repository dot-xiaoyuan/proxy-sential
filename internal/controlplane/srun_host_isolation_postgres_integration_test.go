package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

func TestSRunHostChangeNativeIsolation(t *testing.T) {
	s, actor := srunIsolatedReplayServer(t)
	s.operations.doc = emptyOperationsDocument()
	s.reader = configuredProbeAudit{db: s.operations.db}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, actor)
	var name string
	if err := s.operations.db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(name) {
		t.Fatal("dedicated acceptance database required")
	}
	db := s.operations.db
	id := "host-isolation-" + shortToken(12)
	oldSource, oldSensor := "srun4k:legacy-"+id, "srun4k-direct:legacy-"+id
	if _, err := db.ExecContext(ctx, `INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,connector_type,action_mapping,encrypted_secret,mode,enabled,shadow_ready,shadow_started_at,shadow_validation_since,shadow_candidate_count,shadow_reviewed_count,shadow_accuracy,updated_by) VALUES($1,'isolated','http://192.0.2.1:8001','srun4k','{}',''::bytea,'active',true,true,now()-interval '8 days',now()-interval '8 days',10,10,1,'isolated-operator')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO srun4k_integrations(connector_id,host,source,sensor_id,reconcile_interval_hours,event_channel_state,connection_state,last_tested_at,last_synced_at,last_test_result_order,last_sync_result_order,last_health_result_order,identity_accounts,identity_sessions,products,groups_count,controls) VALUES($1,'192.0.2.1',$2,$3,6,'healthy','healthy',now(),now(),7,8,9,81,81,4,2,3)`, id, oldSource, oldSensor); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO enforcement_identity_sources(connector_id,public_config,state,observed_at,record_count) VALUES($1,jsonb_build_object('source',$2::text,'sensor_id',$3::text,'enabled',true),'healthy',now(),81)`, id, oldSource, oldSensor); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO srun4k_group_catalog(source,group_id,name,active,observed_at) VALUES($1,'1','old group',true,now())`, oldSource); err != nil {
		t.Fatal(err)
	}
	save := func(host string, interval int) srun4KIntegration {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"host": host, "reconcile_interval_hours": interval})
		r := httptest.NewRequest("PUT", "/api/v1/integrations/srun4k/"+id, strings.NewReader(string(payload))).WithContext(ctx)
		w := httptest.NewRecorder()
		s.saveSRun4K(w, r, id)
		if w.Code != 200 {
			t.Fatalf("address edit failed: status=%d body=%s", w.Code, w.Body.String())
		}
		var item srun4KIntegration
		if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
		return item
	}
	t.Run("same_host_keeps_identity", func(t *testing.T) {
		item := save("192.0.2.1", 6)
		if item.Source != oldSource || item.SensorID != oldSensor {
			t.Fatalf("same-address save changed source: %+v", item)
		}
	})
	assertOrders := func(expected int64) {
		t.Helper()
		var health, test, sync int64
		if err := db.QueryRowContext(ctx, `SELECT last_health_result_order,last_test_result_order,last_sync_result_order FROM srun4k_integrations WHERE connector_id=$1`, id).Scan(&health, &test, &sync); err != nil {
			t.Fatal(err)
		}
		if expected == 0 && (health != 0 || test != 0 || sync != 0) {
			t.Fatal("new host retained old result order")
		}
		if expected == 9 && (health != 9 || test != 7 || sync != 8) {
			t.Fatal("same host reset result order")
		}
	}
	assertOrders(9)
	var fresh srun4KIntegration
	t.Run("new_host_requires_new_identity_and_validation", func(t *testing.T) {
		s.setNativeRuntime(id, NativeActionRuntime{TestAccount: "old-controller"})
		fresh = save("192.0.2.2", 6)
		assertOrders(0)
		if _, available := s.nativeRuntime(id); available {
			t.Fatal("failed new-host credential lookup kept old controller runtime")
		}
		if s.operations.doc.Connectors[id].Mode != "shadow" {
			t.Fatal("in-memory connector retained old controller admission")
		}
		if _, registered := s.srunIdentityRegistration(ctx, store.IdentityScope{Source: oldSource, SensorID: oldSensor}); registered {
			t.Fatal("previous controller identity still auto-registered")
		}
		if interval, registered := s.srunIdentityRegistration(ctx, store.IdentityScope{Source: fresh.Source, SensorID: fresh.SensorID}); !registered || interval != 21600 {
			t.Fatal("new controller identity not registered with its current interval")
		}
		if fresh.Source == oldSource || fresh.SensorID == oldSensor || fresh.Source == "srun4k:"+id {
			t.Fatalf("new host reused old namespace: %+v", fresh)
		}
		if fresh.LastTestedAt != nil || fresh.LastSyncedAt != nil || fresh.IdentityAccounts != 0 || fresh.IdentitySessions != 0 || fresh.Products != 0 || fresh.Groups != 0 || fresh.Controls != 0 || fresh.EventChannelState != "waiting" || fresh.ConnectionState != "pending" {
			t.Fatalf("new host retained old validation: %+v", fresh)
		}
		var mode string
		var ready bool
		var started, validated *time.Time
		var candidates, reviewed int
		var accuracy float64
		if err := db.QueryRowContext(ctx, `SELECT mode,shadow_ready,shadow_started_at,shadow_validation_since,shadow_candidate_count,shadow_reviewed_count,shadow_accuracy FROM enforcement_connectors WHERE connector_id=$1`, id).Scan(&mode, &ready, &started, &validated, &candidates, &reviewed, &accuracy); err != nil {
			t.Fatal(err)
		}
		if mode != "shadow" || ready || started != nil || validated != nil || candidates != 0 || reviewed != 0 || accuracy != 0 {
			t.Fatalf("old controller approval remained: %s %v %v %v %d %d %v", mode, ready, started, validated, candidates, reviewed, accuracy)
		}
		var enabled bool
		var state, source string
		var observed *time.Time
		var version int
		if err := db.QueryRowContext(ctx, `SELECT (public_config->>'enabled')::boolean,state,public_config->>'source',observed_at,config_version FROM enforcement_identity_sources WHERE connector_id=$1`, id).Scan(&enabled, &state, &source, &observed, &version); err != nil {
			t.Fatal(err)
		}
		if enabled || state != "pending" || source != oldSource || observed != nil || version <= 1 {
			t.Fatalf("old managed source remains eligible: %v %s %s %v %d", enabled, state, source, observed, version)
		}
	})
	t.Run("retry_and_interval_edit_keep_new_identity", func(t *testing.T) {
		retry := save("192.0.2.2", 6)
		edited := save("192.0.2.2", 12)
		if retry.Source != fresh.Source || edited.Source != fresh.Source || edited.SensorID != fresh.SensorID {
			t.Fatal("retry or interval edit rotated source")
		}
	})
	t.Run("return_to_old_address_gets_another_namespace", func(t *testing.T) {
		back := save("192.0.2.1", 6)
		if back.Source == fresh.Source || back.Source == oldSource || back.SensorID == oldSensor {
			t.Fatal("return to original address reactivated historical identity")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM srun4k_group_catalog WHERE source=$1`, oldSource).Scan(&count); err != nil || count != 1 {
			t.Fatalf("historical evidence deleted: %d %v", count, err)
		}
	})
	t.Run("audit_rejection_rolls_back_configuration", func(t *testing.T) {
		before, err := s.loadSRun4K(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `CREATE FUNCTION reject_host_save_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private fixture rejection'; END $$; CREATE TRIGGER reject_host_save BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_host_save_audit()`); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(ctx, `DROP TRIGGER reject_host_save ON audit_logs`)
		w := httptest.NewRecorder()
		r := httptest.NewRequest("PUT", "/api/v1/integrations/srun4k/"+id, strings.NewReader(`{"host":"192.0.2.3"}`)).WithContext(ctx)
		s.saveSRun4K(w, r, id)
		if w.Code != 503 {
			t.Fatalf("unaudited save accepted: status=%d", w.Code)
		}
		after, err := s.loadSRun4K(ctx, id)
		if err != nil || after.Host != before.Host || after.Source != before.Source || after.SensorID != before.SensorID {
			t.Fatalf("rejected save changed registration: %+v %v", after, err)
		}
	})
}
