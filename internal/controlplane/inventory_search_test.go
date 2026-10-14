package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInventorySearchTypeValidationAndCacheIsolation(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	r := &inventoryModeReader{Reader: s.reader}
	s.reader = r
	for _, q := range []string{"search_type=invalid&q=x", "search_type=ip&q=account", "search_type=mac&q=bad"} {
		for _, path := range []string{"/device-inventory", "/device-inventory/metadata"} {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1"+path+"?"+q, nil))
			if w.Code != 400 {
				t.Fatalf("%s: %d", q, w.Code)
			}
		}
	}
	if len(r.queries) != 0 {
		t.Fatal("invalid search reached database")
	}
	for _, q := range []string{"search_type=account&q=Student-A", "search_type=all&q=Student-A", "search_type=account&q=Student-A"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/device-inventory?"+q, nil))
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	if len(r.queries) != 3 || r.queries[0].Q != "Student-A" || r.queries[0].InventorySearchType != "account" || r.queries[1].InventorySearchType != "all" || r.queries[2].InventorySearchType != "account" {
		t.Fatalf("search semantics: %+v", r.queries)
	}
}

func TestDeviceInventoryRejectsLegacyOffsetCursor(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	r := &inventoryModeReader{Reader: s.reader}
	s.reader = r
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/device-inventory?cursor=20", nil))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "bad_cursor") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(r.queries) != 0 {
		t.Fatal("legacy cursor reached the storage reader")
	}
}
func TestInventoryRawEvidenceKeepsEventPermission(t *testing.T) {
	if got := requiredPermission(http.MethodGet, "/endpoints/terminal/observations"); got != "identity:read" {
		t.Fatal("trace permission changed", got)
	}
	for _, record := range []string{"snapshot:abc", "session:abc"} {
		if got := requiredPermission(http.MethodGet, "/endpoints/terminal/observations/"+record+"/evidence"); got != "events:read" {
			t.Fatal("raw evidence bypassed event permission", got)
		}
	}
}
