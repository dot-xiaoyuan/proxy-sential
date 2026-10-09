package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/store"
	"strconv"
	"testing"
	"time"
)

type inventoryModeReader struct {
	store.Reader
	queries     []store.Query
	routerCalls int
}

func (r *inventoryModeReader) RouterObservationSummaries(context.Context, []string) (map[string]evidence.RouterAssessment, error) {
	r.routerCalls++
	return map[string]evidence.RouterAssessment{}, nil
}

func (r *inventoryModeReader) ListDeviceInventory(_ context.Context, q store.Query) (store.DeviceInventoryListPage, error) {
	r.queries = append(r.queries, q)
	return store.DeviceInventoryListPage{Items: []store.DeviceInventoryListItem{{EndpointID: "test", CurrentIP: "192.0.2.1"}}, Page: store.Page{Limit: 20, Total: 35001}, Facets: store.DeviceFilterFacets{Brands: []string{"Dell"}}}, nil
}
func TestDeviceInventoryMetadataIsIndependentAndLightPageOmitsTotal(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	reader := &inventoryModeReader{Reader: s.reader}
	s.reader = reader
	for _, path := range []string{"/api/v1/device-inventory?view=recent&window=24h&include_metadata=false", "/api/v1/device-inventory/metadata?view=recent&window=24h"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if path == "/api/v1/device-inventory?view=recent&window=24h&include_metadata=false" {
			var page map[string]json.RawMessage
			_ = json.Unmarshal(result["page"], &page)
			if _, ok := page["total"]; ok {
				t.Fatal("light list blocks on a total")
			}
		} else if string(result["total"]) != "35001" {
			t.Fatalf("metadata: %s", w.Body.String())
		}
		if w.Header().Get("Server-Timing") == "" {
			t.Fatal("missing request diagnostics")
		}
	}
	if len(reader.queries) != 2 || !reader.queries[0].InventorySkipMetadata || !reader.queries[1].InventoryMetadataOnly {
		t.Fatalf("queries: %+v", reader.queries)
	}
}
func TestDeviceInventoryCanonicalCacheAndRefresh(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	reader := &inventoryModeReader{Reader: s.reader}
	s.reader = reader
	for _, query := range []string{"view=recent&window=24h", "window=24h&view=recent", "view=recent&window=24h&refresh=true", "window=24h&view=recent"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/device-inventory?"+query, nil))
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	if len(reader.queries) != 2 {
		t.Fatalf("reads=%d, want cached + manual refresh", len(reader.queries))
	}
	if reader.routerCalls != 2 {
		t.Fatalf("cached enrichment reads=%d, want 2", reader.routerCalls)
	}
}

func TestDeviceInventoryMetadataCacheIgnoresPagination(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	reader := &inventoryModeReader{Reader: s.reader}
	s.reader = reader
	for _, query := range []string{"view=recent&window=24h&limit=20&cursor=0&brand=Dell", "brand=dell&cursor=20&limit=50&window=24h&view=recent"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/device-inventory/metadata?"+query, nil))
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	if len(reader.queries) != 1 || reader.routerCalls != 0 {
		t.Fatalf("metadata reads=%d enrichment=%d", len(reader.queries), reader.routerCalls)
	}
}

func TestDeviceInventoryCachesAreBoundedAndExpire(t *testing.T) {
	c := newDeviceInventoryPageCache(time.Second)
	calls := 0
	load := func(context.Context) (store.DeviceInventoryListPage, error) {
		calls++
		return store.DeviceInventoryListPage{}, nil
	}
	for i := 0; i < 200; i++ {
		_, err := c.get(context.Background(), strconv.Itoa(i), load)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(c.entries) != 128 {
		t.Fatalf("cache entries=%d", len(c.entries))
	}
	entry := c.entries["199"]
	entry.expiresAt = time.Now().Add(-time.Second)
	c.entries["199"] = entry
	_, _ = c.get(context.Background(), "199", load)
	if calls != 201 {
		t.Fatalf("expired read calls=%d", calls)
	}
}
