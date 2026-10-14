package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"proxy-sentinel/internal/fingerprint"
	"testing"
)

func TestFingerprintCatalogPaginationAndPermissions(t *testing.T) {
	s := &Server{fingerprints: fingerprint.NewManager("")}
	for _, path := range []string{"/device-fingerprint-library/sources", "/device-fingerprint-library/rules", "/device-fingerprint-library/coverage"} {
		if got := requiredPermission("GET", path); got != "identity:read" {
			t.Fatalf("%s permission: %s", path, got)
		}
	}
	for _, tc := range []struct {
		url, path string
		status    int
	}{{"/device-fingerprint-library/sources?page_size=2", "/device-fingerprint-library/sources", 200}, {"/device-fingerprint-library/sources?page=-1", "/device-fingerprint-library/sources", 400}, {"/device-fingerprint-library/rules?page_size=2&source=recog", "/device-fingerprint-library/rules", 200}, {"/device-fingerprint-library/sources/no-such-source", "/device-fingerprint-library/sources/no-such-source", 404}} {
		w := httptest.NewRecorder()
		s.handleFingerprintCatalog(w, httptest.NewRequest("GET", tc.url, nil), tc.path)
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.url, w.Code)
		}
		if tc.status == 200 {
			var data struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
				t.Fatal(err)
			}
			if len(data.Items) != 2 {
				t.Fatalf("unbounded page %s: %d", tc.url, len(data.Items))
			}
		}
	}
}
