package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestViolationObservationModeCannotBeDisabled(t *testing.T) {
	legacyTransportTestBypass.Store(false)
	defer legacyTransportTestBypass.Store(true)
	if !violationObservationOnly() {
		t.Fatal("violation workflow must remain observation only")
	}
}

func TestObservationBlocksActionAndNotificationTestHTTP(t *testing.T) {
	legacyTransportTestBypass.Store(false)
	defer legacyTransportTestBypass.Store(true)
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer endpoint.Close()
	s := &Server{}
	s.deliverActionRequest(EnforcementAction{ActionID: "test-action"}, ActionConnector{EndpointURL: endpoint.URL}, false)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/test", strings.NewReader("{}"))
	response := httptest.NewRecorder()
	s.runNotificationTest(response, request, nil, notificationTestRequest{})
	if requests.Load() != 0 {
		t.Fatalf("observation mode sent %d external requests", requests.Load())
	}
	if !strings.Contains(response.Body.String(), "external_request_sent") {
		t.Fatalf("test response is not explicit about external request: %s", response.Body.String())
	}
}
