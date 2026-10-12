package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

type fakeSignalArrivals struct {
	arrivals []store.SignalArrival
	err      error
	lookback time.Duration
}

func (f *fakeSignalArrivals) SignalArrivals(_ context.Context, lookback time.Duration) ([]store.SignalArrival, error) {
	f.lookback = lookback
	return f.arrivals, f.err
}

func TestParseSignalExpectationsScopesSourceAndRejectsUnsafeValues(t *testing.T) {
	got, err := ParseSignalExpectations(" ttl=10m, shared-syn-sidecar:ttl=15m ,identity=5m,")
	if err != nil || len(got) != 3 {
		t.Fatalf("parse: %+v %v", got, err)
	}
	if got[1].Source != "shared-syn-sidecar" || got[1].SourceEventType != "ttl" || got[1].MaxAge != 15*time.Minute || got[1].Name() != "shared-syn-sidecar:ttl" {
		t.Fatalf("scoped expectation: %+v", got[1])
	}
	for _, bad := range []string{"ttl", "ttl=10s", "ttl=48h", "ttl=abc", ":ttl=10m", "zeek:=10m", "ttl=10m,ttl=20m"} {
		if _, err := ParseSignalExpectations(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if empty, err := ParseSignalExpectations(""); err != nil || len(empty) != 0 {
		t.Fatalf("empty spec: %+v %v", empty, err)
	}
}

func TestSignalFreshnessDistinguishesStaleMissingAndCollectorScope(t *testing.T) {
	expectations, _ := ParseSignalExpectations("ttl=10m,shared-syn-sidecar:ttl=10m,dhcp=10m,identity=10m")
	arrivals := []store.SignalArrival{
		{Source: "packet-sidecar", SourceEventType: "ttl", AgeSeconds: 30, LastSeen: time.Now()},
		{Source: "zeek", SourceEventType: "dhcp", AgeSeconds: 3600, LastSeen: time.Now().Add(-time.Hour)},
		{Source: "ncu-srun4k", SourceEventType: "identity", AgeSeconds: -2, LastSeen: time.Now()},
	}
	signals, stale := evaluateSignalFreshness(expectations, arrivals)
	status := map[string]string{}
	for _, item := range signals {
		status[item.Signal] = item.Status
	}
	// Router TTL arriving must not hide that the shared-access SYN collector is silent.
	if status["ttl"] != "ready" || status["shared-syn-sidecar:ttl"] != "missing" || status["dhcp"] != "stale" || status["identity"] != "ready" {
		t.Fatalf("freshness: %+v", signals)
	}
	if strings.Join(stale, ",") != "dhcp,shared-syn-sidecar:ttl" {
		t.Fatalf("stale list: %v", stale)
	}
	if *signals[3].AgeSeconds != 0 {
		t.Fatalf("clock skew produced negative age: %+v", signals[3])
	}
}

func TestSignalFreshnessMonitorKeepsLastResultWhenQueryFails(t *testing.T) {
	expectations, _ := ParseSignalExpectations("ttl=10m,dhcp=20m")
	reader := &fakeSignalArrivals{arrivals: []store.SignalArrival{{Source: "packet-sidecar", SourceEventType: "ttl", AgeSeconds: 5}, {Source: "zeek", SourceEventType: "dhcp", AgeSeconds: 5}}}
	monitor := newSignalFreshnessMonitor(reader, expectations)
	if monitor.current().health.Status != "pending" {
		t.Fatal("monitor reported freshness before the first check")
	}
	monitor.refresh(context.Background())
	if reader.lookback != 40*time.Minute {
		t.Fatalf("lookback should cover twice the longest window: %v", reader.lookback)
	}
	if snapshot := monitor.current(); snapshot.health.Status != "ready" || len(snapshot.signals) != 2 {
		t.Fatalf("healthy snapshot: %+v", snapshot)
	}
	reader.err = errors.New("clickhouse timeout")
	monitor.refresh(context.Background())
	snapshot := monitor.current()
	if snapshot.health.Status != "delayed" || !strings.Contains(snapshot.health.Error, "clickhouse timeout") || len(snapshot.signals) != 2 {
		t.Fatalf("query failure must be visible without discarding the last arrivals: %+v", snapshot)
	}
	if newSignalFreshnessMonitor(reader, nil) != nil {
		t.Fatal("monitor started without expectations")
	}
}

func TestStaleSignalsDegradeStatusWithoutFailingReadiness(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	expectations, _ := ParseSignalExpectations("ttl=10m,shared-syn-sidecar:ttl=10m")
	s.signalFreshness = newSignalFreshnessMonitor(&fakeSignalArrivals{arrivals: []store.SignalArrival{{Source: "packet-sidecar", SourceEventType: "ttl", AgeSeconds: 5}}}, expectations)
	s.signalFreshness.refresh(context.Background())

	ready := httptest.NewRecorder()
	s.handleReadiness(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var body struct {
		Status     string                     `json:"status"`
		Components map[string]componentHealth `json:"components"`
	}
	if err := json.Unmarshal(ready.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	signals := body.Components["signals"]
	if ready.Code != http.StatusOK || body.Status != "ready" {
		t.Fatalf("a silent collector must not roll a release back: %d %s", ready.Code, ready.Body.String())
	}
	if signals.Status != "stale" || !strings.Contains(signals.Error, "shared-syn-sidecar:ttl") || len(signals.Signals) != 2 {
		t.Fatalf("stale signal hidden from readiness detail: %+v", signals)
	}

	system := httptest.NewRecorder()
	s.handleSystemStatus(system, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	if !strings.Contains(system.Body.String(), `"status":"degraded"`) {
		t.Fatalf("system status should report degraded: %s", system.Body.String())
	}

	metrics := httptest.NewRecorder()
	s.handleMetrics(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := metrics.Body.String()
	if !strings.Contains(text, `proxy_sentinel_signal_stale{signal="shared-syn-sidecar:ttl"} 1`) || !strings.Contains(text, `proxy_sentinel_signal_age_seconds{signal="ttl"} 5`) || strings.Contains(text, `proxy_sentinel_signal_age_seconds{signal="shared-syn-sidecar:ttl"}`) {
		t.Fatalf("signal metrics: %s", text)
	}
}
