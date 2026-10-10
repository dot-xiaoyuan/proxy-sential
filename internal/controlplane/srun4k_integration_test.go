package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

func TestSRun4KReadOnlyMutationAllowlist(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
		allow  bool
	}{
		{http.MethodPost, "/integrations/srun4k", true},
		{http.MethodPut, "/integrations/srun4k/one", true},
		{http.MethodPost, "/integrations/srun4k/one/test", true},
		{http.MethodPost, "/integrations/srun4k/one/sync", true},
		{http.MethodPost, "/integrations/srun4k/one/authorization", true},
		{http.MethodDelete, "/integrations/srun4k/one", false},
		{http.MethodPost, "/integrations/srun4k/one/other", false},
		{http.MethodPost, "/actions", false},
		{http.MethodPut, "/integrations/identity/bridge", false},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if got := srun4KReadOnlyMutationAllowed(tc.method, tc.path); got != tc.allow {
				t.Fatalf("allow=%v, want %v", got, tc.allow)
			}
		})
	}
}

func srun4KTestIntegrationRow(authorizationReady bool) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"connector_id", "host", "authorization_database_host", "online_redis_host", "catalog_redis_host", "event_redis_host", "northbound_api_host", "source", "sensor_id", "reconcile_interval_hours", "event_channel_state", "connection_state", "last_error", "last_tested_at", "last_synced_at", "identity_accounts", "identity_sessions", "products", "groups_count", "controls", "last_identity_poll_at", "last_identity_event_at", "authorization_refreshed_at", "authorization_ready", "authorization_database_state", "online_redis_state", "catalog_redis_state", "event_redis_state", "northbound_api_state"}).AddRow("one", "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.1", "srun4k:one", "one", 6, "waiting", "healthy", "", nil, nil, 0, 0, 0, 0, 0, nil, nil, nil, authorizationReady, "healthy", "healthy", "healthy", "pending", "healthy")
}

func TestSRun4KRepeatedHostKeepsExistingConnectorAndSource(t *testing.T) {
	for _, requested := range []string{"", "existing", "different"} {
		t.Run("requested-"+requested, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`SELECT connector_id FROM srun4k_integrations WHERE host=\$1`).WithArgs("192.0.2.190").WillReturnRows(sqlmock.NewRows([]string{"connector_id"}).AddRow("existing"))
			mock.ExpectRollback()
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			id, err := resolveSRunConnectorID(context.Background(), tx, "192.0.2.190", requested)
			if requested == "different" {
				if !errors.Is(err, errSRunHostConflict) {
					t.Fatalf("host conflict not reported: %v", err)
				}
			} else if err != nil || id != "existing" {
				t.Fatalf("repeated host replaced connector: id=%s error=%v", id, err)
			}
			tx.Rollback()
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSRunIdentitySnapshotIDIncludesObservationAndSource(t *testing.T) {
	one := 1
	request := identitySnapshotRequest{
		IdentityScope: store.IdentityScope{Source: "srun4k:office", SensorID: "srun4k-direct:office"},
		ObservedAt:    time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), IntervalSeconds: 21600,
		Complete: true, ExpectedCount: &one,
		Records: []map[string]string{{"account_id": "test-account", "session_id": "session", "ip": "192.0.2.1"}},
	}
	getID := func() string {
		t.Helper()
		id, err := srunIdentitySnapshotIDContext(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := getID()
	if first != getID() {
		t.Fatal("retry of identical snapshot changed its id")
	}
	request.ObservedAt = request.ObservedAt.Add(6 * time.Hour)
	if first == getID() {
		t.Fatal("unchanged members prevented a fresh calibration")
	}
	request.ObservedAt = request.ObservedAt.Add(-6 * time.Hour)
	request.Source = "srun4k:other"
	if first == getID() {
		t.Fatal("snapshot id crossed identity sources")
	}
}

func TestSRun4KConnectionContractOnlyAcceptsHostAndOptionalInterval(t *testing.T) {
	for _, path := range []string{"/integrations/srun4k", "/api/v1/integrations/srun4k"} {
		if _, _, collection, ok := srun4KPath(path); !ok || !collection {
			t.Fatalf("collection path not recognized: %s", path)
		}
	}
	request := httptest.NewRequest("POST", "/api/v1/integrations/srun4k", strings.NewReader(`{"host":"192.168.0.190"}`))
	response := httptest.NewRecorder()
	got, err := decodeSRunRequest(response, request)
	if err != nil || got.Host != "192.168.0.190" || got.ReconcileIntervalHours != 6 {
		t.Fatalf("simplified 4K request rejected: %+v %v", got, err)
	}
	request = httptest.NewRequest("POST", "/api/v1/integrations/srun4k", strings.NewReader(`{"host":"192.168.0.190","username":"must-not-be-http-input"}`))
	if _, err = decodeSRunRequest(httptest.NewRecorder(), request); err == nil {
		t.Fatal("deployment credential field accepted by public integration API")
	}
}

func TestSRun4KRedisChannelsUseSeparateDeploymentPorts(t *testing.T) {
	for _, defaults := range []SRun4KDefaults{
		{RedisPassword: "deployment-secret"},
		{RedisPort: 16380, RedisCatalogPort: 16382, RedisPassword: "deployment-secret"},
	} {
		server := &Server{srun4KDefaults: defaults}
		item := srun4KIntegration{Host: "192.0.2.190"}
		online := server.srunRedis(item)
		catalog := server.srunCatalogRedis(item)
		defer online.Close()
		defer catalog.Close()
		if online.Options().Addr != "192.0.2.190:16380" || catalog.Options().Addr != "192.0.2.190:16382" {
			t.Fatalf("Redis source channels mixed: %s %s", online.Options().Addr, catalog.Options().Addr)
		}
		if online.Options().Password != "deployment-secret" || catalog.Options().Password != "deployment-secret" {
			t.Fatal("deployment password not used for both read-only channels")
		}
	}
}

func TestSRun4KPolicyAlwaysBindsItsManagedConnector(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{operations: &operationsState{db: db}}
	definition := policy.Definition{
		Scope:  policy.Scope{Sources: []string{"srun4k:srun4k-office"}},
		Stages: []policy.Stage{{Action: "disconnect", ConnectorID: "wrong-connector"}},
	}
	mock.ExpectQuery(`SELECT connector_id FROM srun4k_integrations WHERE source=\$1`).WithArgs("srun4k:srun4k-office").WillReturnRows(sqlmock.NewRows([]string{"connector_id"}).AddRow("srun4k-office"))
	if err = server.bindSRunPolicyConnector(context.Background(), &definition); err != nil {
		t.Fatal(err)
	}
	if definition.Stages[0].ConnectorID != "srun4k-office" {
		t.Fatalf("connector=%q", definition.Stages[0].ConnectorID)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSRun4KPolicyRejectsUnsupportedAction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{operations: &operationsState{db: db}}
	definition := policy.Definition{
		Scope:  policy.Scope{Sources: []string{"srun4k:srun4k-office"}},
		Stages: []policy.Stage{{Action: "rate_limit"}},
	}
	mock.ExpectQuery(`SELECT connector_id FROM srun4k_integrations WHERE source=\$1`).WithArgs("srun4k:srun4k-office").WillReturnRows(sqlmock.NewRows([]string{"connector_id"}).AddRow("srun4k-office"))
	if err = server.bindSRunPolicyConnector(context.Background(), &definition); err == nil {
		t.Fatal("4K policy accepted unsupported rate-limit action")
	}
}

func TestSRun4KHostAndRouteValidation(t *testing.T) {
	for _, value := range []string{"192.168.0.190", "2001:db8::10", "auth.example.edu"} {
		if !validSRunHost(value) {
			t.Fatalf("valid host rejected: %s", value)
		}
	}
	for _, value := range []string{"", "https://192.168.0.190", "user@host", "bad host"} {
		if validSRunHost(value) {
			t.Fatalf("invalid host accepted: %s", value)
		}
	}
	id, operation, collection, ok := srun4KPath("/api/v1/integrations/srun4k/office/sync")
	if !ok || collection || id != "office" || operation != "sync" {
		t.Fatalf("sync route mismatch: %q %q %t %t", id, operation, collection, ok)
	}
}

func TestSRun4KStatusKeepsPerChannelProgress(t *testing.T) {
	channels := srun4KChannelStates("failed", "waiting", "online_redis: connection refused")
	if channels["authorization_database"] != "healthy" || channels["online_redis"] != "failed" || channels["northbound_api"] != "pending" || channels["event_channel"] != "waiting" {
		t.Fatalf("unexpected channel status: %#v", channels)
	}
}

func TestSRun4KDatabaseFallsBackToEncryptedConfigurationForSameHost(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{operations: &operationsState{db: db}, actionMasterKey: []byte("srun4k-test-master-key-1234")}
	encrypted, err := server.encryptConnectorSecret("database-secret")
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(map[string]any{"host": "192.168.0.190", "port": 3506, "database": "srun4k", "username": "icc", "tls": false})
	mock.ExpectQuery(`SELECT public_config,encrypted_password FROM enforcement_4k_databases`).WithArgs("192.168.0.190").WillReturnRows(sqlmock.NewRows([]string{"public_config", "encrypted_password"}).AddRow(public, []byte(encrypted)))
	configured, err := server.srunDatabase(context.Background(), srun4KIntegration{Host: "192.168.0.190"})
	if err != nil {
		t.Fatal(err)
	}
	if configured.Host != "192.168.0.190" || configured.Username != "icc" || configured.Password != "database-secret" {
		t.Fatalf("unexpected compatible database configuration: %#v", configured)
	}
}
