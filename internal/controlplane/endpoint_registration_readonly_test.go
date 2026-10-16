package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyEndpointRegistrationRetainsGuardsAndAudit(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.auth.enabled = true
	s.auth.sessions["registration-admin"] = authSession{User: localUser{ID: "admin", Role: "admin"}, CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)}
	path := "/endpoints/mac:aa:bb:cc:dd:ee:01/registration"
	body := `{"registration_status":"registered","owner_name":"登记回放","asset_tag":"asset-1","registration_note":"登记资料"}`
	request := func(method, path, body, cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := request(http.MethodPost, path, body, "", ""); w.Code != 401 {
		t.Fatalf("authentication: %d %s", w.Code, w.Body.String())
	}
	if w := request(http.MethodPost, path, body, "registration-admin", ""); w.Code != 403 || !strings.Contains(w.Body.String(), "csrf_failed") {
		t.Fatalf("CSRF: %d %s", w.Code, w.Body.String())
	}
	if w := request(http.MethodPost, path, `{}`, "registration-admin", "csrf"); w.Code != 400 {
		t.Fatalf("validation: %d %s", w.Code, w.Body.String())
	}
	if w := request(http.MethodPost, path, body, "registration-admin", "csrf"); w.Code != 200 || !strings.Contains(w.Body.String(), "asset-1") {
		t.Fatalf("registration: %d %s", w.Code, w.Body.String())
	}
	if w := request(http.MethodGet, "/endpoints/mac:aa:bb:cc:dd:ee:01/identity", "", "registration-admin", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "登记回放") {
		t.Fatalf("profile: %d %s", w.Code, w.Body.String())
	}
	if w := request(http.MethodGet, "/audit-logs", "", "registration-admin", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "endpoints.registration.update") {
		t.Fatalf("audit: %d %s", w.Code, w.Body.String())
	}
	for _, blocked := range []string{"/endpoints/mac:aa:bb:cc:dd:ee:01/name-note", "/endpoints/mac:aa:bb:cc:dd:ee:01/registration/execute", "/endpoints/nested/path/registration", "/actions/test/execute", "/policy-executions/test/approve", "/policies"} {
		if w := request(http.MethodPost, blocked, `{}`, "registration-admin", "csrf"); w.Code != 403 || !strings.Contains(w.Body.String(), "read_only") {
			t.Fatalf("blocked %s: %d %s", blocked, w.Code, w.Body.String())
		}
	}
	s.auth.sessions["registration-admin"] = authSession{User: localUser{ID: "viewer", Role: "viewer"}, CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)}
	if w := request(http.MethodPost, path, body, "registration-admin", "csrf"); w.Code != 403 || !strings.Contains(w.Body.String(), "permission_denied") {
		t.Fatalf("permission: %d %s", w.Code, w.Body.String())
	}
}
