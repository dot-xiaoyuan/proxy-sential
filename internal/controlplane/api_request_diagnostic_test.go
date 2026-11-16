package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSlowAPIDiagnosticRedactsPathAndQuery(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/actions/account-secret-123?token=query-secret-456", nil)
	response := httptest.NewRecorder()
	observed := &apiRequestStatusWriter{ResponseWriter: response}
	observed.WriteHeader(http.StatusServiceUnavailable)
	_, _ = observed.Write([]byte("failure"))
	if got := observed.statusCode(); got != http.StatusServiceUnavailable || response.Code != got {
		t.Fatalf("status wrapper changed response: wrapper=%d response=%d", got, response.Code)
	}
	var lines []string
	observeSlowAPIRequest(&apiSlowLogLimiter{}, time.Unix(1, 0), request,
		observed.statusCode(), 15*time.Millisecond, func(line string) { lines = append(lines, line) })
	if len(lines) != 1 || !strings.Contains(lines[0], "method=GET route=actions.item status=503 duration_ms=15") {
		t.Fatalf("missing bounded API diagnostic: %q", lines)
	}
	if strings.Contains(lines[0], "account-secret") || strings.Contains(lines[0], "query-secret") || strings.Contains(lines[0], "token") {
		t.Fatalf("diagnostic exposed request data: %q", lines[0])
	}
	networkRequest := httptest.NewRequest(http.MethodGet, "/api/v1/discovery/devices?mode=passive&type=router&search=query-secret-456", nil)
	observeSlowAPIRequest(&apiSlowLogLimiter{}, time.Unix(1, 0), networkRequest, 503, time.Millisecond,
		func(line string) { lines = append(lines, line) })
	if len(lines) != 2 || !strings.Contains(lines[1], "route=discovery.network_assets") || strings.Contains(lines[1], "query-secret") {
		t.Fatalf("network asset category leaked query data: %q", lines)
	}
	for _, tc := range []struct{ path, category string }{
		{"/api/v1/actions", "actions.list"},
		{"/api/v1/behavior-reports/outbox", "reports.outbox.list"},
		{"/api/v1/behavior-reports/outbox/report-secret", "reports.outbox.item"},
		{"/api/v1/router-observations/role-secret", "router_observations.item"},
		{"/api/v1/discovery/devices", "discovery.devices"},
		{"/api/v1/discovery/devices?mode=passive&type=router&search=query-secret", "discovery.network_assets"},
		{"/api/v1/discovery/devices?mode=passive&type=access_point&token=query-secret", "discovery.network_assets"},
		{"/api/v1/discovery/devices?mode=passive&type=secret", "discovery.devices"},
		{"/api/v1/unknown-secret", "api.other"},
	} {
		if got := apiDiagnosticRoute(httptest.NewRequest(http.MethodGet, tc.path, nil)); got != tc.category || strings.Contains(got, "secret") {
			t.Fatalf("category for %q = %q, want %q", tc.path, got, tc.category)
		}
	}
}

func TestSlowAPIDiagnosticThresholdAndRateLimit(t *testing.T) {
	limiter := &apiSlowLogLimiter{}
	start := time.Unix(100, 0)
	var lines []string
	emit := func(line string) { lines = append(lines, line) }
	request := func(method, path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Method = method
		return r
	}
	observeSlowAPIRequest(limiter, start, request(http.MethodGet, "/api/v1/router-observations"), 200, time.Second, emit)
	if len(lines) != 0 {
		t.Fatal("a fast successful request was logged")
	}
	for index := 0; index < slowAPILogBurst+1; index++ {
		observeSlowAPIRequest(limiter, start, request("BAD\nsecret", "/api/v1/unknown-secret"), 200, time.Second+time.Millisecond, emit)
	}
	if len(lines) != slowAPILogBurst {
		t.Fatalf("rate limiter emitted %d lines, want %d", len(lines), slowAPILogBurst)
	}
	for _, line := range lines {
		if strings.Contains(line, "secret") || !strings.Contains(line, "method=OTHER route=api.other") {
			t.Fatalf("unbounded or unsafe method/path: %q", line)
		}
	}
	for index := 0; index < slowAPILogBurst+1; index++ {
		observeSlowAPIRequest(limiter, start, request(http.MethodGet, "/api/v1/discovery/devices"), 503, time.Millisecond, emit)
	}
	observeSlowAPIRequest(limiter, start, request(http.MethodGet, "/api/v1/actions"), 503, time.Millisecond, emit)
	observeSlowAPIRequest(limiter, start, request(http.MethodGet, "/api/v1/behavior-reports/outbox"), 503, time.Millisecond, emit)
	if len(lines) != slowAPILogBurst*2+2 || !strings.Contains(lines[len(lines)-2], "route=actions.list") || !strings.Contains(lines[len(lines)-1], "route=reports.outbox.list") {
		t.Fatalf("busy categories hid action/report diagnostics: %q", lines)
	}
	observeSlowAPIRequest(limiter, start.Add(slowAPILogWindow), request(http.MethodGet, "/api/v1/actions"), 500, time.Millisecond, emit)
	if len(lines) != slowAPILogBurst*2+3 || !strings.Contains(lines[len(lines)-1], "route=actions.list status=500") {
		t.Fatalf("next window or 5xx logging failed: %q", lines)
	}
}
