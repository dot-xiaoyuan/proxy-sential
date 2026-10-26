package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

type streamRiskCutoverAPIReader struct {
	store.Reader
	sensor string
}

func (r *streamRiskCutoverAPIReader) GetStreamRiskCutoverStatus(_ context.Context, sensor string) (store.StreamRiskCutoverStatus, bool, error) {
	r.sensor = sensor
	return store.StreamRiskCutoverStatus{SensorID: sensor, CancelID: "audit-1", CanceledSubjects: 12, AcceptedAfter: time.Now().UTC()}, true, nil
}

func TestStreamRiskCutoverAPIUsesServerSensorAndShowsAuditedGap(t *testing.T) {
	reader := &streamRiskCutoverAPIReader{}
	server := &Server{reader: reader, sensorID: "sensor-a"}
	response := httptest.NewRecorder()
	server.handleStreamRiskCutover(response, httptest.NewRequest(http.MethodGet, "/risks/stream-cutover?sensor_id=other", nil))
	if response.Code != http.StatusOK || reader.sensor != "sensor-a" {
		t.Fatalf("status=%d sensor=%s", response.Code, reader.sensor)
	}
	var body struct {
		Active bool                          `json:"active"`
		Status store.StreamRiskCutoverStatus `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || !body.Active || body.Status.CanceledSubjects != 12 {
		t.Fatalf("invalid audited gap response: %+v %v", body, err)
	}
}
