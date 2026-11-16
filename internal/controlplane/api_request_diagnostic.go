package controlplane

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	slowAPIRequestThreshold = time.Second
	slowAPILogWindow        = 10 * time.Second
	slowAPILogBurst         = 2
)

// The writer records the first response status without changing the response.
// Unwrap lets net/http's ResponseController reach the underlying writer.
type apiRequestStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *apiRequestStatusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *apiRequestStatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *apiRequestStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *apiRequestStatusWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

type apiSlowLogLimiter struct {
	mu      sync.Mutex
	buckets map[string]apiSlowLogBucket
}

type apiSlowLogBucket struct {
	windowStart time.Time
	emitted     int
}

// Categories are fixed by apiDiagnosticRoute, including the single unknown
// bucket. Busy discovery reads cannot hide action or report failures.
func (l *apiSlowLogLimiter) allow(now time.Time, category string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = make(map[string]apiSlowLogBucket)
	}
	bucket := l.buckets[category]
	if bucket.windowStart.IsZero() || now.Before(bucket.windowStart) || !now.Before(bucket.windowStart.Add(slowAPILogWindow)) {
		bucket.windowStart, bucket.emitted = now, 0
	}
	if bucket.emitted >= slowAPILogBurst {
		return false
	}
	bucket.emitted++
	l.buckets[category] = bucket
	return true
}

var controlPlaneSlowAPILogs apiSlowLogLimiter

func logSlowAPIRequest(request *http.Request, status int, elapsed time.Duration) {
	if status < http.StatusInternalServerError && elapsed <= slowAPIRequestThreshold {
		return
	}
	observeSlowAPIRequest(&controlPlaneSlowAPILogs, time.Now(), request, status, elapsed, func(line string) { log.Print(line) })
}

func observeSlowAPIRequest(limiter *apiSlowLogLimiter, now time.Time, request *http.Request, status int, elapsed time.Duration, emit func(string)) {
	if status < http.StatusInternalServerError && elapsed <= slowAPIRequestThreshold {
		return
	}
	category := apiDiagnosticRoute(request)
	if !limiter.allow(now, category) {
		return
	}
	emit(fmt.Sprintf("api_request_slow method=%s route=%s status=%d duration_ms=%d", apiDiagnosticMethod(request.Method), category, status, elapsed.Milliseconds()))
}

func apiDiagnosticMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

// Every result is a fixed label. Raw paths, identifiers and query parameters
// never enter the diagnostic line, including for routes unknown to this list.
func apiDiagnosticRoute(request *http.Request) string {
	path := strings.TrimPrefix(request.URL.Path, "/api/v1")
	switch {
	case path == "/actions":
		return "actions.list"
	case path == "/actions/connectors" || strings.HasPrefix(path, "/actions/connectors/"):
		return "actions.connectors"
	case strings.HasPrefix(path, "/actions/"):
		return "actions.item"
	case path == "/behavior-reports/outbox":
		return "reports.outbox.list"
	case strings.HasPrefix(path, "/behavior-reports/outbox/"):
		return "reports.outbox.item"
	case path == "/behavior-reports/channels" || strings.HasPrefix(path, "/behavior-reports/channels/"):
		return "reports.channels"
	case path == "/router-observations":
		return "router_observations.list"
	case strings.HasPrefix(path, "/router-observations/"):
		return "router_observations.item"
	case path == "/discovery/devices":
		if request.URL.Query().Get("mode") == "passive" {
			kind := request.URL.Query().Get("type")
			if kind == "router" || kind == "access_point" {
				return "discovery.network_assets"
			}
		}
		return "discovery.devices"
	case path == "/discovery/history":
		return "discovery.history"
	case path == "/discovery" || strings.HasPrefix(path, "/discovery/"):
		return "discovery.other"
	case path == "/shared-access" || strings.HasPrefix(path, "/shared-access/"):
		return "shared_access"
	case path == "/device-inventory" || strings.HasPrefix(path, "/device-inventory/"):
		return "device_inventory"
	case path == "/events" || strings.HasPrefix(path, "/events/"):
		return "events"
	case path == "/dpi" || strings.HasPrefix(path, "/dpi/"):
		return "dpi"
	case path == "/audit-logs" || strings.HasPrefix(path, "/audit-logs/"):
		return "audit"
	case path == "/integrations/identity" || strings.HasPrefix(path, "/integrations/identity/"):
		return "identity_integration"
	default:
		return "api.other"
	}
}
