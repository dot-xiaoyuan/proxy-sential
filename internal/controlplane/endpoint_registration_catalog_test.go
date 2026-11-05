package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxy-sentinel/internal/store"
)

type registrationCatalogTestReader struct {
	store.Reader
	listCalls, countCalls int
	query                 store.EndpointRegistrationQuery
}

func (r *registrationCatalogTestReader) ListEndpointRegistrations(_ context.Context, q store.EndpointRegistrationQuery) (store.EndpointRegistrationPage, error) {
	r.listCalls++
	r.query = q
	return store.EndpointRegistrationPage{Items: []store.EndpointRegistrationRecord{{EndpointID: "mac:02:00:00:00:00:01", PrimaryMAC: "02:00:00:00:00:01", RegistrationStatus: "registered", RegistrationDetails: store.EndpointRegistrationDetails{Name: "教学打印机", RegisteredIP: "10.0.0.8"}}}, Limit: q.Limit, AsOf: "2026-11-05T14:00:00Z"}, nil
}
func (r *registrationCatalogTestReader) EndpointRegistrationMetadata(_ context.Context, q store.EndpointRegistrationQuery) (store.EndpointRegistrationMetadata, error) {
	r.countCalls++
	r.query = q
	return store.EndpointRegistrationMetadata{Total: 1, AsOf: "2026-11-05T14:00:00Z"}, nil
}

func TestRegistrationCatalogRoutesAndIndependentStatistics(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	r := &registrationCatalogTestReader{Reader: s.reader}
	s.reader = r
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1"+path, nil))
		return w
	}
	w := request("/endpoints/registrations?status=registered&type=printer&mac=02-AA-BB-CC-DD-01&limit=20")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "教学打印机") || strings.Contains(w.Body.String(), `"total"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if r.query.Status != "registered" || r.query.DeviceType != "printer" || r.query.MAC != "02:aa:bb:cc:dd:01" || r.countCalls != 0 {
		t.Fatalf("query=%+v count_calls=%d", r.query, r.countCalls)
	}
	w = request("/endpoints/registrations/metadata?status=registered&type=printer")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":1`) || r.listCalls != 1 {
		t.Fatalf("metadata: %d %s", w.Code, w.Body.String())
	}
	for _, suffix := range []string{"?limit=0", "?limit=201", "?limit=bad", "?status=bad", "?ownership_class=bad", "?cursor=bad", "?offset=0", "?mac=invalid", "?mac=ff:ff:ff:ff:ff:ff"} {
		if w = request("/endpoints/registrations" + suffix); w.Code != 400 {
			t.Fatalf("%s: %d %s", suffix, w.Code, w.Body.String())
		}
	}
}
