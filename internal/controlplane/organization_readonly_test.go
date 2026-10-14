package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyOrganizationConfigurationRetainsGuards(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	audit := &bridgeAddressAudit{Reader: s.reader}
	s.reader = audit
	s.auth.enabled = true
	s.auth.sessions["org-session"] = authSession{User: localUser{ID: "org-admin", Role: "admin"}, CSRFToken: "org-csrf", ExpiresAt: time.Now().Add(time.Hour)}
	request := func(path, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1"+path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "org-session"})
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	for _, item := range []struct{ path, body string }{
		{"/organization/campuses", `{"campus_id":"ncu","code":"NCU-QH","name":"前湖校区"}`},
		{"/organization/buildings", `{"building_id":"lib","campus_id":"ncu","name":"图书馆"}`},
		{"/organization/network-zones", `{"network_zone_id":"zone","campus_id":"ncu","name":"慧源社区"}`},
		{"/organization/access-points", `{"access_point_id":"ap","campus_id":"ncu","name":"AP"}`},
	} {
		if w := request(item.path, item.body, ""); w.Code != 403 || !strings.Contains(w.Body.String(), "csrf_failed") {
			t.Fatalf("CSRF guard: %d %s", w.Code, w.Body.String())
		}
		if w := request(item.path, item.body, "org-csrf"); w.Code != 201 {
			t.Fatalf("save: %d %s", w.Code, w.Body.String())
		}
	}
	if len(audit.entries) != 4 {
		t.Fatalf("expected four audit records, got %d", len(audit.entries))
	}
	for _, entry := range audit.entries {
		if entry.Actor != "org-admin" || entry.Action != "organization.update" {
			t.Fatalf("unexpected audit: %+v", entry)
		}
	}
	for _, path := range []string{"/actions/execute", "/policies", "/organization/campuses/delete", "/organization/import"} {
		if w := request(path, `{}`, "org-csrf"); w.Code != 403 || !strings.Contains(w.Body.String(), "read_only") {
			t.Fatalf("write restriction lost for %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	s.auth.sessions["org-session"] = authSession{User: localUser{ID: "org-viewer", Role: "viewer"}, CSRFToken: "org-csrf", ExpiresAt: time.Now().Add(time.Hour)}
	if w := request("/organization/campuses", `{}`, "org-csrf"); w.Code != 403 || !strings.Contains(w.Body.String(), "permission_denied") {
		t.Fatalf("permission guard lost: %d %s", w.Code, w.Body.String())
	}
}
