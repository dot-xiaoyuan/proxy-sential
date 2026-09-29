package controlplane

import (
	"net/http/httptest"
	"testing"
)

func TestNativeObservationEndpointScopeAndBounds(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.operations.doc.Actions["one"] = EnforcementAction{ActionID: "one", AccountID: "account", SessionID: "session", ConnectorID: "connector", IdempotencyKey: "key"}
	for _, tt := range []struct {
		path   string
		status int
	}{
		{"missing/native-observations", 404},
		{"one/native-observations?before=-1", 400},
		{"one/native-observations?before=9999999999999999999999999", 400},
		{"one/native-observations?limit=101", 400},
		{"one/native-observations", 503},
	} {
		r := httptest.NewRequest("GET", "/api/v1/actions/"+tt.path, nil)
		w := httptest.NewRecorder()
		s.handleActions(w, r)
		if w.Code != tt.status {
			t.Fatalf("%s: %d %s", tt.path, w.Code, w.Body.String())
		}
	}
	if got := requiredPermission("GET", "/actions/one/native-observations"); got != "actions:read" {
		t.Fatalf("incorrect permission %s", got)
	}
}
