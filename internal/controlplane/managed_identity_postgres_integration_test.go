package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagedIdentityPostgresVersionAndFailure(t *testing.T) {
	s, actor := taskIntegrationServer(t)
	s.actionMasterKey = []byte("01234567890123456789012345678901")
	id := "managed-test-" + shortToken(12)
	_, err := s.operations.db.Exec(`INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,encrypted_secret,updated_by,connector_type) VALUES($1,'isolated','https://192.0.2.190:8001','', 'isolated','srun4k')`, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.operations.db.Exec(`DELETE FROM audit_logs WHERE target=$1`, id)
		s.operations.db.Exec(`DELETE FROM enforcement_identity_sources WHERE connector_id=$1`, id)
		s.operations.db.Exec(`DELETE FROM enforcement_connectors WHERE connector_id=$1`, id)
	})
	config := managedIdentityConfig{Kind: "online_equipment", MaxRecords: 10000, Enabled: true, UserCIDRs: []string{"192.0.2.0/24"}}
	config.Source = id
	config.SensorID = "isolated"
	config.CampusID = id
	config.AccessDomain = "office-test"
	call := func(method string, version int64) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"configuration": config, "config_version": version})
		r := httptest.NewRequest(method, "/api/v1/actions/connectors/"+id+"/identity-source", bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, actor))
		w := httptest.NewRecorder()
		s.handleActions(w, r)
		return w
	}
	if w := call("PUT", 0); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if w := call("PUT", 0); w.Code != 409 {
		t.Fatal("stale version accepted")
	}
	items, err := s.managedIdentityRegistrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var item managedIdentityRegistration
	for _, candidate := range items {
		if candidate.ID == id {
			item = candidate
		}
	}
	s.reconcileManagedIdentity(item)
	w := call("GET", 0)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "inventory_completeness_unproven") {
		t.Fatalf("missing blocker: %s", w.Body.String())
	}
	// A previous task must not alter the status of a newly saved version.
	if w := call("PUT", 1); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s.markManagedIdentityFailure(item, "old_task_must_not_write")
	if w := call("GET", 0); strings.Contains(w.Body.String(), "old_task_must_not_write") || !strings.Contains(w.Body.String(), "pending") {
		t.Fatal("old task overwrote new version")
	}
	config.Kind = "complete_inventory"
	config.InventoryURL = "https://192.0.2.190:8001/inventory"
	config.Token = "isolated-inventory-token"
	if w := call("PUT", 2); w.Code != 200 || strings.Contains(w.Body.String(), config.Token) {
		t.Fatalf("credential save invalid: %s", w.Body.String())
	}
	if w := call("GET", 0); strings.Contains(w.Body.String(), config.Token) {
		t.Fatal("credential echoed")
	}
	var encrypted []byte
	if s.operations.db.QueryRow(`SELECT encrypted_token FROM enforcement_identity_sources WHERE connector_id=$1`, id).Scan(&encrypted) != nil || strings.Contains(string(encrypted), config.Token) {
		t.Fatal("credential stored unencrypted")
	}
	config.Token = ""
	if w := call("PUT", 3); w.Code != 200 {
		t.Fatal("blank same-url credential not preserved")
	}
	config.InventoryURL = "https://192.0.2.191:8001/inventory"
	if w := call("PUT", 4); w.Code != 400 {
		t.Fatal("credential reused across changed origins")
	}
}

func TestManagedIdentityCompleteInventoryAndScope(t *testing.T) {
	s, actor := taskIntegrationServer(t)
	_ = actor
	s.actionMasterKey = []byte("01234567890123456789012345678901")
	reader := &snapshotReader{}
	s.reader = reader
	id := "managed-complete-" + shortToken(12)
	observed := time.Now().UTC().Truncate(time.Microsecond)
	outside := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer isolated-token" {
			t.Error("missing inventory credential")
		}
		ip := "192.0.2.93"
		if outside {
			ip = "198.51.100.93"
		}
		json.NewEncoder(w).Encode(map[string]any{"schema_version": "online-inventory/v1", "instance_id": "mock-existing-api", "observed_at": observed, "campus_id": id, "access_domain": "office", "complete": true, "expected_count": 1, "rows": []map[string]string{{"session_id": "raw17", "rad_online_id": "17", "user_name": "test", "ip": ip, "add_time": "1750000000"}}})
	}))
	defer srv.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	_, err := s.operations.db.Exec(`INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,certificate_pem,encrypted_secret,updated_by,connector_type) VALUES($1,'isolated',$2,$3,'','isolated','srun4k')`, id, srv.URL, string(certificate))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.operations.db.Exec(`DELETE FROM enforcement_identity_sources WHERE connector_id=$1`, id)
		s.operations.db.Exec(`DELETE FROM enforcement_connectors WHERE connector_id=$1`, id)
	})
	cfg := managedIdentityConfig{Kind: "complete_inventory", MaxRecords: 10000, Enabled: true, UserCIDRs: []string{"192.0.2.0/24"}, InventoryURL: srv.URL + "/inventory"}
	cfg.Source = id
	cfg.SensorID = "isolated"
	cfg.CampusID = id
	cfg.AccessDomain = "office"
	raw, _ := json.Marshal(cfg)
	encrypted, err := s.encryptConnectorSecret("isolated-token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.operations.db.Exec(`INSERT INTO enforcement_identity_sources(connector_id,public_config,encrypted_token) VALUES($1,$2,$3)`, id, raw, []byte(encrypted))
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.managedIdentityRegistrations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var item managedIdentityRegistration
	for _, candidate := range items {
		if candidate.ID == id {
			item = candidate
		}
	}
	s.reconcileManagedIdentity(item)
	var state, blocker string
	if s.operations.db.QueryRow(`SELECT state,blocker FROM enforcement_identity_sources WHERE connector_id=$1`, id).Scan(&state, &blocker) != nil || state != "healthy" || reader.commits != 1 {
		t.Fatalf("complete sync state=%s blocker=%s commits=%d", state, blocker, reader.commits)
	}
	if !strings.Contains(reader.snapshot.Events[0].RawRef["session_id_source"].(string), "derived") {
		t.Fatal("missing provenance")
	}
	outside = true
	s.reconcileManagedIdentity(item)
	if s.operations.db.QueryRow(`SELECT state,blocker FROM enforcement_identity_sources WHERE connector_id=$1`, id).Scan(&state, &blocker) != nil || state != "unavailable" || blocker != "inventory_address_outside_scope" || reader.commits != 1 {
		t.Fatal("outside scope published or historical snapshot lost")
	}
	// The currently saved version fences a stale successful network result too.
	outside = false
	s.operations.db.Exec(`UPDATE enforcement_identity_sources SET config_version=config_version+1,state='pending' WHERE connector_id=$1`, id)
	s.reconcileManagedIdentity(item)
	if reader.commits != 1 {
		t.Fatal("stale configuration committed")
	}
	var before, after int64
	s.operations.db.QueryRow(`SELECT config_version FROM enforcement_identity_sources WHERE connector_id=$1`, id).Scan(&before)
	_, err = s.operations.db.Exec(`UPDATE enforcement_connectors SET endpoint_url='https://192.0.2.191:8001' WHERE connector_id=$1`, id)
	if err != nil {
		t.Fatal(err)
	}
	s.operations.db.QueryRow(`SELECT config_version,state,blocker FROM enforcement_identity_sources WHERE connector_id=$1`, id).Scan(&after, &state, &blocker)
	if after != before+1 || state != "pending" || blocker != "connector_configuration_changed" {
		t.Fatal("management configuration did not invalidate identity epoch")
	}
}
