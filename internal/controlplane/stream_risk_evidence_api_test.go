package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/store"
)

type streamRiskEvidenceAPIReader struct {
	store.Reader
	sensor, kind, subject, fact string
	found                       bool
}

func (r *streamRiskEvidenceAPIReader) GetStreamRiskEvidence(_ context.Context, sensor, kind, subject, fact string) (evidence.Evidence, bool, error) {
	r.sensor, r.kind, r.subject, r.fact = sensor, kind, subject, fact
	return evidence.Evidence{EvidenceID: fact}, r.found, nil
}

func TestStreamRiskEvidenceAPIRequiresCurrentScopedFact(t *testing.T) {
	reader := &streamRiskEvidenceAPIReader{found: true}
	server := &Server{reader: reader, sensorID: "sensor-a"}
	for _, path := range []string{
		"/risks/stream-evidence?subject_id=192.0.2.8",
		"/risks/stream-evidence?subject_type=endpoint&subject_id=192.0.2.8&evidence_id=fact-1",
	} {
		response := httptest.NewRecorder()
		server.handleStreamRiskEvidence(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid request %q status=%d", path, response.Code)
		}
	}
	path := "/risks/stream-evidence?sensor_id=other&subject_id=192.0.2.8&evidence_id=fact-1"
	response := httptest.NewRecorder()
	server.handleStreamRiskEvidence(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK || reader.sensor != "sensor-a" || reader.kind != "ip" || reader.subject != "192.0.2.8" || reader.fact != "fact-1" ||
		!strings.Contains(response.Body.String(), `"evidence_id":"fact-1"`) {
		t.Fatalf("scoped fact status=%d reader=%+v body=%s", response.Code, reader, response.Body.String())
	}
	reader.found = false
	response = httptest.NewRecorder()
	server.handleStreamRiskEvidence(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing current fact status=%d", response.Code)
	}
}
