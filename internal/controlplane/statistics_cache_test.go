package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecognitionStatisticsCacheDoesNotServeExpiredBody(t *testing.T) {
	value := statisticsResponse{body: []byte(`{"total_endpoints":42}`), contentType: "application/json", status: http.StatusOK,
		asOf: time.Now().Add(-5*time.Minute - time.Second)}
	response := httptest.NewRecorder()
	statisticsWriteRoute(response, "/device-recognition/summary", value)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "total_endpoints") ||
		!strings.Contains(response.Body.String(), "recognition_statistics_not_ready") {
		t.Fatalf("expired recognition body escaped: status=%d body=%s", response.Code, response.Body.String())
	}
	value.asOf = time.Now()
	response = httptest.NewRecorder()
	statisticsWriteRoute(response, "/device-recognition/summary", value)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "total_endpoints") {
		t.Fatalf("fresh recognition body unavailable: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRecognitionStatisticsPrewarmRetrySurvivesCallerCancellation(t *testing.T) {
	cache := newStatisticsCache()
	caller, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/device-recognition/summary", nil).WithContext(caller)
	var calls atomic.Int32
	dispatch := func(w http.ResponseWriter, _ *http.Request, _ string) {
		if calls.Add(1) == 1 {
			writeError(w, http.StatusInternalServerError, "read_device_recognition_summary_failed", "recognition statistics not prepared")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total_endpoints":42}`))
	}
	response := httptest.NewRecorder()
	cache.serve(response, request, "/device-recognition/summary", dispatch)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold response = %d, want 503", response.Code)
	}
	cancel()
	cache.mu.Lock()
	loaded := cache.entries[statisticsKey(request, "/device-recognition/summary")].loading
	cache.mu.Unlock()
	select {
	case <-loaded:
	case <-time.After(2*recognitionCatalogRetryDelay + 2*time.Second):
		t.Fatal("catalog prewarm did not finish after caller cancellation")
	}
	response = httptest.NewRecorder()
	cache.serve(response, request, "/device-recognition/summary", dispatch)
	if response.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("catalog retry result: status=%d calls=%d body=%s", response.Code, calls.Load(), response.Body.String())
	}
}

func TestRecognitionStatisticsDoesNotRetryClickHouseFailure(t *testing.T) {
	cache := newStatisticsCache()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/device-recognition/summary", nil)
	var calls atomic.Int32
	dispatch := func(w http.ResponseWriter, _ *http.Request, _ string) {
		calls.Add(1)
		writeError(w, http.StatusInternalServerError, "read_device_recognition_summary_failed", "query event attribution: ClickHouse unavailable")
	}
	response := httptest.NewRecorder()
	cache.serve(response, request, "/device-recognition/summary", dispatch)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold response = %d, want 503", response.Code)
	}
	cache.mu.Lock()
	loaded := cache.entries[statisticsKey(request, "/device-recognition/summary")].loading
	cache.mu.Unlock()
	select {
	case <-loaded:
	case <-time.After(time.Second):
		t.Fatal("failed ClickHouse scan did not finish")
	}
	if calls.Load() != 1 {
		t.Fatalf("ClickHouse failure triggered %d scans, want one", calls.Load())
	}
}

func TestRecognitionStatisticsBackgroundFillIsNonblockingAndSingleFlight(t *testing.T) {
	cache := newStatisticsCache()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/device-recognition/summary", nil)
	started, release := make(chan struct{}), make(chan struct{})
	var scans atomic.Int32
	dispatch := func(w http.ResponseWriter, _ *http.Request, _ string) {
		if scans.Add(1) == 1 {
			close(started)
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total_endpoints":42}`))
	}
	response := httptest.NewRecorder()
	returned := make(chan struct{})
	go func() {
		cache.serve(response, request, "/device-recognition/summary", dispatch)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("first summary request waited for the ClickHouse scan")
	}
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold summary response = %d, want 503", response.Code)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background summary scan did not start")
	}
	for range 10 {
		response = httptest.NewRecorder()
		cache.serve(response, request, "/device-recognition/summary", dispatch)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("pending summary response = %d, want 503", response.Code)
		}
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("pending requests started %d scans, want one", got)
	}
	cache.mu.Lock()
	loaded := cache.entries[statisticsKey(request, "/device-recognition/summary")].loading
	cache.mu.Unlock()
	close(release)
	select {
	case <-loaded:
	case <-time.After(time.Second):
		t.Fatal("background summary scan did not finish")
	}
	for range 10 {
		response = httptest.NewRecorder()
		cache.serve(response, request, "/device-recognition/summary", dispatch)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "total_endpoints") {
			t.Fatalf("prepared summary response = %d body=%s", response.Code, response.Body.String())
		}
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("fresh repeated requests started %d scans, want one", got)
	}
}

func TestRecognitionStatisticsExpiredCacheStartsOneRebuildWithoutServingOldData(t *testing.T) {
	cache := newStatisticsCache()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/device-recognition/summary", nil)
	key := statisticsKey(request, "/device-recognition/summary")
	cache.entries[key] = &statisticsEntry{
		value: statisticsResponse{body: []byte(`{"total_endpoints":999}`), contentType: "application/json", status: http.StatusOK,
			asOf: time.Now().Add(-recognitionStatisticsMaxAge - time.Second)},
		lastLoad: time.Now().Add(-recognitionStatisticsRetryDelay - time.Second),
	}
	release := make(chan struct{})
	var scans atomic.Int32
	dispatch := func(w http.ResponseWriter, _ *http.Request, _ string) {
		scans.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total_endpoints":42}`))
	}
	for range 10 {
		response := httptest.NewRecorder()
		cache.serve(response, request, "/device-recognition/summary", dispatch)
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "999") {
			t.Fatalf("expired data escaped: status=%d body=%s", response.Code, response.Body.String())
		}
	}
	cache.mu.Lock()
	loaded := cache.entries[key].loading
	cache.mu.Unlock()
	if loaded == nil {
		t.Fatal("expired summary did not start a rebuild")
	}
	close(release)
	select {
	case <-loaded:
	case <-time.After(time.Second):
		t.Fatal("expired summary rebuild did not finish")
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("expired requests started %d scans, want one", got)
	}
	response := httptest.NewRecorder()
	cache.serve(response, request, "/device-recognition/summary", dispatch)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"total_endpoints":42`) {
		t.Fatalf("rebuilt summary unavailable: status=%d body=%s", response.Code, response.Body.String())
	}
}
