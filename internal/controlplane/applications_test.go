package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"proxy-sentinel/internal/appdomain"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

type applicationTestSource struct{}

func (applicationTestSource) ScanApplicationEvents(context.Context, appdomain.Scan) ([]normalized.Event, error) {
	return []normalized.Event{}, nil
}
func TestApplicationEndpoints(t *testing.T) {
	dir := t.TempDir()
	server := NewServer(Options{ShadowDir: dir, FingerprintDir: filepath.Join(dir, "fp")})
	get := func(method, path string, body []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, httptest.NewRequest(method, "/api/v1"+path, bytes.NewReader(body)))
		return w
	}
	if w := get("GET", "/application-library", nil); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"enabled":false`)) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := get("GET", "/application-activity", nil); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if w := get("POST", "/application-library/config", []byte(`{"enabled":true,"update_url":"http://localhost:8081/api/features/application-domain/bundles/v1/download"}`)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := get("GET", "/application-library", nil); !bytes.Contains(w.Body.Bytes(), []byte(`"enabled":true`)) {
		t.Fatal(w.Body.String())
	}
	server.readOnly = true
	if w := get("POST", "/application-library/config", []byte(`{"enabled":false}`)); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := get("POST", "/application-library/pull", []byte(`{}`)); w.Code != 403 {
		t.Fatal(w.Code)
	}
	server.readOnly = false
	service, err := appdomain.OpenService(filepath.Join(dir, "applications"), applicationTestSource{})
	if err != nil {
		t.Fatal(err)
	}
	server.applications = service
	raw, err := appdomain.ExampleBundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if w := get("POST", "/application-library/import", raw); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := get("POST", "/application-library/import", []byte("bad")); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := get("GET", "/application-activity?window=24h", nil); w.Code != 200 || !json.Valid(w.Body.Bytes()) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := get("GET", "/application-activity?ip=bad", nil); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := get("GET", "/application-activity/observations?offset=-1", nil); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := get("POST", "/application-library/reclassify", nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	server.readOnly = true
	if w := get("POST", "/application-library/rollback", []byte(`{"version":"contract-fixture-v1"}`)); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if requiredPermission(http.MethodPost, "/application-library/import") != "device-fingerprint-library:update" || requiredPermission(http.MethodGet, "/application-activity") != "dpi:read" || requiredPermission(http.MethodGet, "/application-activity/unknown-domains") != "exports:read" {
		t.Fatal("permissions missing")
	}
}
