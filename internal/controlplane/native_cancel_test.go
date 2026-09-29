package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeCompletedDisconnectCannotPretendToRestoreSession(t *testing.T) {
	ops, err := newOperationsState("", "")
	if err != nil {
		t.Fatal(err)
	}
	ops.doc.Actions["native"] = EnforcementAction{ActionID: "native", ActionType: "disconnect", Status: "succeeded", PolicyParameters: PolicyActionParameters{NativeSelected: true}}
	s := &Server{operations: ops}
	w := httptest.NewRecorder()
	s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/actions/native/revoke", nil), "native")
	if w.Code != http.StatusConflict {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if len(ops.doc.Actions) != 1 {
		t.Fatal("created a fictitious release action")
	}
}
