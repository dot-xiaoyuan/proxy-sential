package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/store"
)

type bridgeAddressAudit struct {
	store.Reader
	entries []store.AuditLog
}

func (a *bridgeAddressAudit) AppendAuditLog(_ context.Context, entry store.AuditLog) error {
	a.entries = append(a.entries, entry)
	return nil
}

func TestFourKAddressUsesCommittedIdentityHostOnly(t *testing.T) {
	defaults := IdentityBridgeDefaults{}.normalized()
	for _, test := range []struct {
		name    string
		host    string
		version int64
		want    bool
	}{
		{"committed", "222.204.3.224", 1, true},
		{"not_started", "", 0, false},
		{"uncommitted", "222.204.3.225", 0, false},
		{"invalid", "https://222.204.3.224", 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := identityBridgeFourKAddress(defaults, test.host, test.version)
			if (address != nil) != test.want {
				t.Fatalf("address=%+v", address)
			}
			if address != nil && (address.Host != test.host || address.ConfigVersion != test.version || address.Source != defaults.Source || address.ConfigurationPath != "/integrations/identity/bridge") {
				t.Fatalf("address did not inherit committed identity configuration: %+v", address)
			}
		})
	}
}

func TestReadOnlyFourKAddressUpdateRetainsPermissionAndCSRF(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	server.operations.db = db
	audit := &bridgeAddressAudit{Reader: server.reader}
	server.reader = audit
	server.auth.enabled = true
	server.auth.sessions["test-session"] = authSession{User: localUser{ID: "admin-test", Role: "admin"}, CSRFToken: "test-csrf", ExpiresAt: time.Now().Add(time.Hour)}
	request := func(method, path, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(`{"host":"222.204.3.224"}`))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-session"})
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	server.operations.db = nil
	if response := request(http.MethodPost, "/integrations/srun4k", ""); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "csrf_failed") {
		t.Fatalf("4K configuration lost CSRF protection: %s", response.Body.String())
	}
	if response := request(http.MethodPost, "/integrations/srun4k", "test-csrf"); response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), `"code":"read_only"`) {
		t.Fatalf("4K configuration was blocked by the read-only switch: %d %s", response.Code, response.Body.String())
	}
	server.operations.db = db
	for _, path := range []string{"/actions/connectors", "/actions/execute", "/actions/emergency-stop"} {
		response := request(http.MethodPost, path, "test-csrf")
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"read_only"`) {
			t.Fatalf("write protection lost: %s %s", path, response.Body.String())
		}
	}
	if response := request(http.MethodPut, "/integrations/identity/bridge", ""); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "csrf_failed") {
		t.Fatalf("CSRF check lost: %s", response.Body.String())
	}
	mock.ExpectQuery(`UPDATE identity_bridge_configs SET desired_host`).WithArgs(ncuIdentityBridgeID, "222.204.3.224", "admin-test").WillReturnRows(sqlmock.NewRows([]string{"config_version"}).AddRow(1))
	if response := request(http.MethodPut, "/integrations/identity/bridge", "test-csrf"); response.Code != http.StatusAccepted {
		t.Fatalf("single address update blocked: %d %s", response.Code, response.Body.String())
	}
	if len(audit.entries) != 1 || audit.entries[0].Actor != "admin-test" || audit.entries[0].Action != "integration.identity_bridge.configure" {
		t.Fatalf("address update audit missing: %+v", audit.entries)
	}
	server.auth.sessions["test-session"] = authSession{User: localUser{ID: "viewer-test", Role: "viewer"}, CSRFToken: "test-csrf", ExpiresAt: time.Now().Add(time.Hour)}
	if response := request(http.MethodPut, "/integrations/identity/bridge", "test-csrf"); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "permission_denied") {
		t.Fatalf("permission check lost: %s", response.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectorListReportsGlobalReadOnly(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		server := &Server{readOnly: readOnly, operations: &operationsState{doc: emptyOperationsDocument()}}
		recorder := httptest.NewRecorder()
		server.handleConnectors(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/actions/connectors", nil))
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusOK || body["read_only"] != readOnly {
			t.Fatalf("response=%s", recorder.Body.String())
		}
	}
}
