package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/legacy4k"
	"strings"
	"testing"
	"time"
)

func TestNativeAccountPreviewReadOnlyAndScopeExplicit(t *testing.T) {
	ops, err := newOperationsState("", "")
	if err != nil {
		t.Fatal(err)
	}
	ops.doc.Connectors["c"] = ActionConnector{ConnectorID: "c"}
	native := &nativeQueueSandbox{}
	s := &Server{operations: ops, nativeActions: map[string]NativeActionRuntime{"c": {Client: native, CampusID: "lab", AccessDomain: "nas", Read: func(context.Context) (legacy4k.OnlineInventory, error) {
		return legacy4k.OnlineInventory{InstanceID: "boot", ObservedAt: time.Now().UTC(), Rows: []map[string]string{{"add_time": "100", "rad_online_id": "7", "session_id": "sid", "user_name": "test", "ip": "192.0.2.7"}}}, nil
	}}}}
	for _, tc := range []struct {
		account string
		code    int
	}{{"test", 200}, {"", 400}, {"other", 409}} {
		w := httptest.NewRecorder()
		s.handleNativeAccountPreview(w, httptest.NewRequest(http.MethodGet, "/preview?account_id="+tc.account, nil), "c")
		if w.Code != tc.code {
			t.Fatalf("got %d: %s", w.Code, w.Body.String())
		}
		if tc.code == 200 && (!strings.Contains(w.Body.String(), "configured_source_only") || !strings.Contains(w.Body.String(), "fingerprint")) {
			t.Fatal("preview missing confirmation or scope")
		}
	}
	if native.calls.Load() != 0 || len(ops.doc.Actions) != 0 {
		t.Fatal("preview executed an action")
	}
}
