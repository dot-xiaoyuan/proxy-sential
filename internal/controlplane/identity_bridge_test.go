package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestIdentityBridgeRuntimeConfigIsTemplateBoundAndSecretFree(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT desired_host,desired_event_redis_addr,config_version,updated_by,updated_at`).WithArgs(ncuIdentityBridgeID).WillReturnRows(sqlmock.NewRows([]string{"desired_host", "desired_event_redis_addr", "config_version", "updated_by", "updated_at"}).AddRow("222.204.3.224", "222.204.3.227:16384", 3, "operator", now))
	mock.ExpectQuery(`SELECT catalog_redis_host FROM srun4k_integrations`).WithArgs("222.204.3.224").WillReturnRows(sqlmock.NewRows([]string{"catalog_redis_host"}).AddRow("192.0.2.222"))
	server := &Server{
		identityBridge: IdentityBridgeDefaults{},
		identityIngest: &identityIngestState{key: "identity-token"},
		operations:     &operationsState{db: db},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/identity/bridge/runtime-config", nil)
	request.Header.Set("Authorization", "Bearer identity-token")
	recorder := httptest.NewRecorder()
	server.handleIdentityBridgeRuntimeConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, expected := range []string{"222.204.3.224:16380", "192.0.2.222:16382", "222.204.3.227:16384", "list:rad_online", "proxy-sentinel-processing", `"reconcile_interval_seconds":1800`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in %s", expected, body)
		}
	}
	for _, secret := range []string{"password", "community", "token"} {
		if strings.Contains(strings.ToLower(body), secret) {
			t.Fatalf("runtime config exposed secret field %q: %s", secret, body)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBridgeUpdateRejectsNonHostConfiguration(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{operations: &operationsState{db: db}}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/integrations/identity/bridge", strings.NewReader(`{"host":"222.204.3.224","port":16380}`))
	recorder := httptest.NewRecorder()
	server.updateIdentityBridge(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("non-host bridge configuration accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}
