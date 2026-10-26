package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxy-sentinel/internal/store"
)

type streamRiskSubjectAPIReader struct {
	store.Reader
	sensor, kind, id string
}

func (r *streamRiskSubjectAPIReader) GetStreamRiskSubjectState(_ context.Context, sensor, kind, id string) (store.StreamRiskSubjectState, error) {
	r.sensor, r.kind, r.id = sensor, kind, id
	return store.StreamRiskSubjectState{State: "processing"}, nil
}

func TestStreamRiskSubjectAPISeparatesPendingFromNoRecord(t *testing.T) {
	reader := &streamRiskSubjectAPIReader{}
	server := &Server{reader: reader, sensorID: "sensor-a"}
	bad := httptest.NewRecorder()
	server.handleStreamRiskSubject(bad, httptest.NewRequest(http.MethodGet, "/risks/stream-subject", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("missing subject status=%d", bad.Code)
	}
	good := httptest.NewRecorder()
	server.handleStreamRiskSubject(good, httptest.NewRequest(http.MethodGet, "/risks/stream-subject?sensor_id=other&subject_id=192.0.2.8", nil))
	if good.Code != http.StatusOK || reader.sensor != "sensor-a" || reader.kind != "ip" ||
		reader.id != "192.0.2.8" || !strings.Contains(good.Body.String(), `"state":"processing"`) {
		t.Fatalf("subject state status=%d reader=%+v body=%s", good.Code, reader, good.Body.String())
	}
}
