package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSharedObservationAdminCannotBypassGlobalReadOnly(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.auth.enabled = true
	s.auth.sessions["observe-admin"] = authSession{User: localUser{ID: "admin", Role: "admin"}, CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)}
	for _, path := range []string{"/policy-executions/shared-observe-test/approve", "/actions/test/execute", "/shared-access/reviews/test/disconnect"} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1"+path, strings.NewReader(`{}`))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "observe-admin"})
		r.Header.Set("X-CSRF-Token", "csrf")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "read_only") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
