package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/pagination"
	"proxy-sentinel/internal/store"
)

func TestNumberedPaginationKeepsListPermissions(t *testing.T) {
	for _, base := range []string{"/device-inventory", "/endpoints/registrations", "/discovery/devices", "/discovery/history", "/policy-decisions", "/shared-access/reviews", "/shared-access/reviews/r/evidence", "/shared-access/reviews/r/executions", "/endpoints/e/observations", "/risks/stream-current", "/events/stream-index", "/ips/192.0.2.1/traffic-observations", "/ai-relay/usages"} {
		for _, suffix := range []string{"/metadata", "/position"} {
			if got, want := requiredPermission("GET", base+suffix), requiredPermission("GET", base); got != want || got == "" {
				t.Fatalf("permission %s%s=%s want=%s", base, suffix, got, want)
			}
		}
	}
}

type inventoryPositionReader struct {
	store.Reader
	query store.Query
	calls int
}

func (r *inventoryPositionReader) ListDeviceInventory(_ context.Context, q store.Query) (store.DeviceInventoryListPage, error) {
	r.calls++
	r.query = q
	if q.InventoryPositionPage == 99 {
		return store.DeviceInventoryListPage{}, pagination.ErrPageOutOfRange
	}
	cursor := "located-key"
	return store.DeviceInventoryListPage{Page: store.Page{NextCursor: &cursor}, AsOf: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

func TestInventoryPositionRouteUsesOnlyLocatorAndPreservesFilters(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	reader := &inventoryPositionReader{Reader: s.reader}
	s.reader = reader
	for _, tc := range []struct {
		query string
		want  int
	}{{"page=3&limit=50&brand=Dell&view=recent&window=24h", 200}, {"page=99&limit=20", 400}, {"page=0", 400}, {"page=2&limit=201", 400}, {"page=bad", 400}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/device-inventory/position?"+tc.query, nil))
		if w.Code != tc.want {
			t.Fatalf("%s: %d %s", tc.query, w.Code, w.Body.String())
		}
		if tc.want == 200 {
			var got pagination.Position
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Page != 3 || got.Limit != 50 || got.Cursor != "located-key" || reader.query.Brand != "dell" || !reader.query.InventorySkipMetadata || reader.query.InventoryMetadataOnly || reader.query.InventoryCursor != "" {
				t.Fatalf("position=%+v query=%+v", got, reader.query)
			}
		}
	}
	if reader.calls != 2 {
		t.Fatalf("invalid requests reached storage: %d", reader.calls)
	}
}

type registrationPositionReader struct {
	registrationCatalogTestReader
	page int
}

func (r *registrationPositionReader) EndpointRegistrationPosition(_ context.Context, q store.EndpointRegistrationQuery, page int) (pagination.Position, error) {
	r.query = q
	r.page = page
	return pagination.Position{Page: page, Limit: q.Limit, Cursor: "registration-key", AsOf: time.Now().UTC()}, nil
}

func TestRegistrationPositionRoutePreservesFilters(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	reader := &registrationPositionReader{registrationCatalogTestReader: registrationCatalogTestReader{Reader: s.reader}}
	s.reader = reader
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/endpoints/registrations/position?page=5&limit=50&status=registered&type=printer", nil))
	if w.Code != 200 || reader.page != 5 || reader.query.Limit != 50 || reader.query.DeviceType != "printer" || reader.query.Status != "registered" || reader.listCalls != 0 || reader.countCalls != 0 {
		t.Fatalf("position %d %s reader=%+v", w.Code, w.Body.String(), reader)
	}
}

func TestDiscoveryPositionRouteUsesFilteredBoundary(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_DISCOVERY_V2", "")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ", "")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_STREAM_CURRENT_READ", "")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`(?s)matched AS.*classification_status.*SELECT identity_key,device_key,last_seen.*LIMIT 2 OFFSET`).WillReturnRows(sqlmock.NewRows([]string{"identity_key", "device_key", "last_seen"}).AddRow("a", "a", time.Now()).AddRow("b", "b", time.Now()))
	s := &Server{operations: &operationsState{db: db}}
	w := httptest.NewRecorder()
	s.handleDiscovery(w, httptest.NewRequest("GET", "/discovery/devices/position?page=3&limit=20&type=printer&state=identified", nil), "/discovery/devices/position")
	if w.Code != 200 {
		t.Fatalf("position %d %s", w.Code, w.Body.String())
	}
	var got pagination.Position
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Page != 3 || got.Limit != 20 || got.Cursor == "" {
		t.Fatalf("position=%+v", got)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
