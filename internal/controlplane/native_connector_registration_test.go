package controlplane

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestNativeConnectorUsesConfiguredCredentialsWithoutGenericSecret(t *testing.T) {
	for _, configured := range []bool{false, true} {
		s := NewServer(Options{ShadowDir: t.TempDir()})
		if configured {
			s.nativeActions = map[string]NativeActionRuntime{"native": {}}
		}
		r := httptest.NewRequest("POST", "/api/v1/actions/connectors", bytes.NewBufferString(`{"connector_id":"native","name":"native","endpoint_url":"https://192.0.2.190:8001","enabled":true,"mode":"shadow"}`))
		w := httptest.NewRecorder()
		s.handleConnectors(w, r)
		want := 400
		if configured {
			want = 200
		}
		if w.Code != want {
			t.Fatalf("configured=%v: got %d want %d", configured, w.Code, want)
		}
		if configured && s.operations.doc.Connectors["native"].ShadowReady {
			t.Fatal("registration bypassed admission")
		}
	}
}

func TestExplicitNativeConnectorCanBeSavedButCannotFallBackToHMAC(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir()})
	r := httptest.NewRequest("POST", "/api/v1/actions/connectors", bytes.NewBufferString(`{"connector_id":"native","connector_type":"srun4k","name":"native","endpoint_url":"https://192.0.2.190:8001","enabled":false,"mode":"shadow"}`))
	w := httptest.NewRecorder()
	s.handleConnectors(w, r)
	if w.Code != 200 {
		t.Fatalf("registration: %d %s", w.Code, w.Body.String())
	}
	if s.operations.doc.Connectors["native"].ConnectorType != "srun4k" {
		t.Fatal("type lost")
	}
	w = httptest.NewRecorder()
	s.handleConnectorTest(w, httptest.NewRequest("POST", "/api/v1/actions/connectors/native/test", nil), "native")
	if w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("native_runtime_unavailable")) {
		t.Fatalf("missing runtime: %d %s", w.Code, w.Body.String())
	}
}
