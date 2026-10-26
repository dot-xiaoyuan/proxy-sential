package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxy-sentinel/internal/store"
)

type ipTrafficAPIReader struct {
	store.Reader
	query store.IPTrafficObservationQuery
	calls int
	err   error
}

func (r *ipTrafficAPIReader) ListIPTrafficObservations(_ context.Context, q store.IPTrafficObservationQuery) (store.IPTrafficObservationPage, error) {
	r.query = q
	r.calls++
	if r.err != nil {
		return store.IPTrafficObservationPage{}, r.err
	}
	return store.IPTrafficObservationPage{Status: "ready", StreamEventIndexPage: store.StreamEventIndexPage{Items: []store.StreamEventIndexItem{}}}, nil
}

func TestIPTrafficAPIUsesScopedPermissionAndBoundedWindow(t *testing.T) {
	r := &ipTrafficAPIReader{}
	s := &Server{reader: r, sensorID: "sensor-a"}
	for _, suffix := range []string{"", "?from=2026-10-26T06:00:00Z&to=2026-10-27T06:00:00Z", "?from=2026-10-26T06:00:00Z&to=2026-10-26T06:15:00Z&source_owner=other"} {
		w := httptest.NewRecorder()
		s.handleIP(w, httptest.NewRequest(http.MethodGet, "/ips/10.157.2.191/traffic-observations"+suffix, nil), "10.157.2.191/traffic-observations")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %s status=%d", suffix, w.Code)
		}
	}
	if r.calls != 0 {
		t.Fatal("invalid queries reached store")
	}
	w := httptest.NewRecorder()
	s.handleIP(w, httptest.NewRequest(http.MethodGet, "/ips/10.157.2.191/traffic-observations?from=2026-10-26T06:00:00Z&to=2026-10-26T06:15:00Z&protocol=ttl&limit=12", nil), "10.157.2.191/traffic-observations")
	if w.Code != 200 || r.query.SensorID != "sensor-a" || r.query.IP != "10.157.2.191" || r.query.Protocol != "ttl" || r.query.Limit != 12 {
		t.Fatalf("query=%+v status=%d", r.query, w.Code)
	}
	if got := requiredPermission(http.MethodGet, "/ips/10.157.2.191/traffic-observations"); got != "events:read" {
		t.Fatalf("traffic permission=%s", got)
	}
	r.err = errors.New("clickhouse query budget exceeded")
	w = httptest.NewRecorder()
	s.handleIP(w, httptest.NewRequest(http.MethodGet, "/ips/10.157.2.191/traffic-observations?from=2026-10-26T06:00:00Z&to=2026-10-26T06:15:00Z", nil), "10.157.2.191/traffic-observations")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("read failure became empty success: %d %s", w.Code, w.Body.String())
	}
}
