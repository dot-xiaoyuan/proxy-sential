package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/pagination"
	"proxy-sentinel/internal/store"
)

type auxiliaryPaginationReader struct {
	store.Reader
	err           error
	endpointID    string
	endpointQuery store.EndpointObservationQuery
	trafficQuery  store.IPTrafficObservationQuery
	riskSensor    string
	page, limit   int
}

func (r *auxiliaryPaginationReader) EndpointObservationMetadata(_ context.Context, id string, q store.EndpointObservationQuery) (pagination.Metadata, error) {
	r.endpointID = id
	r.endpointQuery = q
	return pagination.Metadata{Total: 41, AsOf: time.Now().UTC()}, r.err
}
func (r *auxiliaryPaginationReader) PositionEndpointObservations(_ context.Context, id string, q store.EndpointObservationQuery, page int) (pagination.Position, error) {
	r.endpointID = id
	r.endpointQuery = q
	r.page = page
	r.limit = q.Limit
	at, _ := time.Parse(time.RFC3339Nano, q.AsOf)
	return pagination.Position{Page: page, Limit: q.Limit, Cursor: "boundary", AsOf: at}, r.err
}
func (r *auxiliaryPaginationReader) IPTrafficObservationMetadata(_ context.Context, q store.IPTrafficObservationQuery) (pagination.Metadata, error) {
	r.trafficQuery = q
	return pagination.Metadata{Total: 21, AsOf: time.Now().UTC()}, r.err
}
func (r *auxiliaryPaginationReader) PositionIPTrafficObservations(_ context.Context, q store.IPTrafficObservationQuery, page int) (pagination.Position, error) {
	r.trafficQuery = q
	r.page = page
	return pagination.Position{Page: page, Limit: q.Limit, Cursor: "boundary", AsOf: time.Now().UTC()}, r.err
}
func (r *auxiliaryPaginationReader) StreamRiskCurrentMetadata(_ context.Context, sensor, kind, level string) (pagination.Metadata, error) {
	r.riskSensor = sensor
	return pagination.Metadata{Total: 21, AsOf: time.Now().UTC()}, r.err
}
func (r *auxiliaryPaginationReader) PositionStreamRiskCurrent(_ context.Context, sensor, kind, level string, page, limit int) (pagination.Position, error) {
	r.riskSensor = sensor
	return pagination.Position{Page: page, Limit: limit, Cursor: "boundary", AsOf: time.Now().UTC()}, r.err
}

func TestAuxiliaryEndpointPaginationPreservesSnapshotAndRejectsMissingPage(t *testing.T) {
	r := &auxiliaryPaginationReader{}
	s := &Server{reader: r}
	w := httptest.NewRecorder()
	s.handleEndpointObservationPagination(w, httptest.NewRequest(http.MethodGet, "/endpoints/a/observations/position?kind=account&value=alice&source=radius&page=3&limit=10&as_of=2026-11-06T00:00:00Z", nil), "a")
	if w.Code != 200 || r.page != 3 || r.limit != 10 || r.endpointQuery.Value != "alice" || r.endpointQuery.AsOf != "2026-11-06T00:00:00Z" || !strings.Contains(w.Body.String(), `"cursor":"boundary"`) {
		t.Fatalf("status=%d query=%+v body=%s", w.Code, r.endpointQuery, w.Body.String())
	}
	r.err = pagination.ErrPageOutOfRange
	w = httptest.NewRecorder()
	s.handleEndpointObservationPagination(w, httptest.NewRequest(http.MethodGet, "/endpoints/a/observations/position?kind=account&page=9", nil), "a")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "page_out_of_range") {
		t.Fatalf("missing page became success: %d %s", w.Code, w.Body.String())
	}
	r.err = errors.New("database down")
	w = httptest.NewRecorder()
	s.handleEndpointObservationPagination(w, httptest.NewRequest(http.MethodGet, "/endpoints/a/observations/metadata?kind=account", nil), "a")
	if w.Code != 503 {
		t.Fatalf("count failure became zero: %d", w.Code)
	}
}

func TestAuxiliaryCurrentPaginationKeepsSensorAndObservationScope(t *testing.T) {
	r := &auxiliaryPaginationReader{}
	s := &Server{reader: r, sensorID: "sensor-a"}
	w := httptest.NewRecorder()
	s.handleIPTrafficObservationPagination(w, httptest.NewRequest(http.MethodGet, "/ips/192.0.2.1/traffic-observations/position?from=2026-11-06T00:00:00Z&to=2026-11-06T00:10:00Z&protocol=ttl&page=2&limit=10", nil), "192.0.2.1")
	if w.Code != 200 || r.trafficQuery.SensorID != "sensor-a" || r.trafficQuery.IP != "192.0.2.1" || r.trafficQuery.Protocol != "ttl" || r.trafficQuery.SourceOwner != "handshake-sidecar" {
		t.Fatalf("status=%d query=%+v", w.Code, r.trafficQuery)
	}
	w = httptest.NewRecorder()
	s.handleIPTrafficObservationPagination(w, httptest.NewRequest(http.MethodGet, "/ips/192.0.2.1/traffic-observations/metadata?sensor_id=other&from=2026-11-06T00:00:00Z&to=2026-11-06T00:10:00Z", nil), "192.0.2.1")
	if w.Code != 400 {
		t.Fatalf("accepted another sensor: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleStreamRiskCurrentPagination(w, httptest.NewRequest(http.MethodGet, "/risks/stream-current/metadata?sensor_id=other&subject_type=account&level=high", nil))
	if w.Code != 200 || r.riskSensor != "sensor-a" {
		t.Fatalf("risk scope changed: %d %s", w.Code, r.riskSensor)
	}
}
