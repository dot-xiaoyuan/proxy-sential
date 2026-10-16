package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAccountAssessmentEndpointsAreRetired(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir()})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/account-assessments"},
		{http.MethodGet, "/api/v1/accounts/student-1/assessment"},
		{http.MethodPost, "/api/v1/accounts/student-1/tag-reviews"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: expected 404, got %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}
