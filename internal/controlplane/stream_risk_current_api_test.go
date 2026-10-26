package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

type streamRiskCurrentAPIReader struct {
	store.Reader
	sensor, kind, level, cursor string
	limit                       int
}

func (r *streamRiskCurrentAPIReader) ListStreamRiskCurrent(_ context.Context, sensor, kind, level, cursor string, limit int) (store.StreamRiskCurrentPage, error) {
	r.sensor, r.kind, r.level, r.cursor, r.limit = sensor, kind, level, cursor, limit
	return store.StreamRiskCurrentPage{Cutoff: time.Now().UTC()}, nil
}

func TestStreamRiskCurrentAPIIsBoundedAndSensorScoped(t *testing.T) {
	reader := &streamRiskCurrentAPIReader{}
	server := &Server{reader: reader, sensorID: "sensor-a"}
	bad := httptest.NewRecorder()
	server.handleStreamRiskCurrent(bad, httptest.NewRequest(http.MethodGet, "/risks/stream-current?limit=9999", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("unbounded risk list status=%d", bad.Code)
	}
	good := httptest.NewRecorder()
	server.handleStreamRiskCurrent(good, httptest.NewRequest(http.MethodGet, "/risks/stream-current?sensor_id=other&subject_type=account&level=high&limit=12&cursor=abc", nil))
	if good.Code != http.StatusOK || reader.sensor != "sensor-a" || reader.kind != "account" ||
		reader.level != "high" || reader.limit != 12 || reader.cursor != "abc" || !strings.Contains(good.Body.String(), "accepted_after") {
		t.Fatalf("scoped risk page status=%d reader=%+v body=%s", good.Code, reader, good.Body.String())
	}
}
