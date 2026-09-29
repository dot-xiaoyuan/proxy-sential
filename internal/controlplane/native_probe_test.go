package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/legacy4k"
	"strings"
	"testing"
	"time"
)

func TestNativeConnectorProbeUsesReadOnlyProtocol(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail bool
		age  time.Duration
		want int
	}{{"healthy", false, 0, 200}, {"api_error", true, 0, 502}, {"stale_inventory", false, time.Minute, 502}, {"future_inventory", false, -time.Minute, 502}} {
		t.Run(tc.name, func(t *testing.T) {
			ops, err := newOperationsState("", "")
			if err != nil {
				t.Fatal(err)
			}
			ops.doc.Connectors["native"] = ActionConnector{ConnectorID: "native", EndpointURL: "http://127.0.0.1:1/must-not-call"}
			sandbox := &nativeQueueSandbox{}
			s := &Server{operations: ops, nativeActions: map[string]NativeActionRuntime{"native": {Client: sandbox, Probe: func(context.Context) (int64, error) {
				if tc.fail {
					return 0, fmt.Errorf("secret-do-not-display")
				}
				return 2, nil
			}, Read: func(context.Context) (legacy4k.OnlineInventory, error) {
				return legacy4k.OnlineInventory{InstanceID: "boot", ObservedAt: time.Now().UTC().Add(-tc.age), Rows: []map[string]string{}}, nil
			}}}}
			w := httptest.NewRecorder()
			s.handleConnectorTest(w, httptest.NewRequest(http.MethodPost, "/test", nil), "native")
			if w.Code != tc.want {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
			if sandbox.calls.Load() != 0 || strings.Contains(w.Body.String(), "secret-do-not-display") {
				t.Fatal("probe mutated controller or leaked error")
			}
			if ops.doc.Connectors["native"].ShadowReady {
				t.Fatal("connectivity granted shadow admission")
			}
		})
	}
}
