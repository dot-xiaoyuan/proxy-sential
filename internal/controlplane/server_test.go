package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/adapter/suricata"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/evaluation"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/shadow"
	"proxy-sentinel/internal/store"
)

func TestShadowRunsEmptyDirectoryReturnsEmptyArrays(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "office-30", ReadOnly: true})

	var runs struct {
		Runs []ShadowRun `json:"runs"`
	}
	getJSON(t, server, "/api/v1/shadow/runs", http.StatusOK, &runs)
	if runs.Runs == nil || len(runs.Runs) != 0 {
		t.Fatalf("expected empty runs array, got %#v", runs.Runs)
	}

	var risks RiskListResponse
	getJSON(t, server, "/api/v1/risks", http.StatusOK, &risks)
	if risks.Items == nil || len(risks.Items) != 0 || risks.Page.Total != 0 {
		t.Fatalf("expected empty risk page, got %#v", risks)
	}
}

func TestShadowEvaluationReturnsLatestReport(t *testing.T) {
	shadowDir := t.TempDir()
	evaluationDir := filepath.Join(shadowDir, "evaluation")
	if err := os.MkdirAll(evaluationDir, 0o755); err != nil {
		t.Fatalf("create evaluation dir: %v", err)
	}
	expected := evaluation.ShadowEvaluationReport{
		GeneratedAt: "2026-08-21T15:00:00Z", RequiredDays: 7, ObservedDays: 8,
		LongestContinuousDays: 8, DaysWithReviews: 0, RunCount: 1010,
		RiskSnapshotCount: 24663, EvaluatedSampleCount: 716, ReviewedSnapshotCount: 0,
		Ready: false, Blockers: []string{"仅 0 天包含人工复核，要求至少 7 天"},
	}
	mustWriteJSON(t, filepath.Join(evaluationDir, "latest.json"), expected)
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "office-30", ReadOnly: true})

	var actual evaluation.ShadowEvaluationReport
	getJSON(t, server, "/api/v1/shadow/evaluation", http.StatusOK, &actual)
	if actual.RunCount != expected.RunCount || actual.ObservedDays != expected.ObservedDays || actual.Ready {
		t.Fatalf("unexpected shadow evaluation: %#v", actual)
	}
}

func TestShadowEvaluationReturnsNotFoundBeforeFirstReport(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "office-30", ReadOnly: true})
	var response ErrorResponse
	getJSON(t, server, "/api/v1/shadow/evaluation", http.StatusNotFound, &response)
	if response.Code != "shadow_evaluation_not_found" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestOverviewAndShadowRunsUseLatestRun(t *testing.T) {
	shadowDir := t.TempDir()
	writeRun(t, shadowDir, "20260727-100000", testRun{
		startedAt: "2026-07-27T10:00:00+08:00",
		risks: []risk.Snapshot{
			riskSnapshot("192.168.0.1", "normal", 20, "2026-07-27T10:00:00+08:00"),
		},
	})
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: "2026-07-27T10:10:00+08:00",
		normalized: suricata.Stats{
			Read: 11, Emitted: 10, Skipped: 1, Malformed: 0, ByType: map[string]int{"device": 2, "http": 8},
		},
		zeekNormalized: zeek.Stats{
			Read: 4, Emitted: 2, Skipped: 2, ByType: map[string]int{"device": 2},
		},
		zeekStatus:     "ok",
		zeekReason:     "zeek dhcp log produced device events",
		zeekPrevOffset: 1000,
		zeekNewOffset:  2000,
		evidence: []evidence.Evidence{
			evidenceItem("evidence-a", "192.168.0.2", "multi_user_agent", "2026-07-27T10:10:01+08:00"),
			evidenceItem("evidence-b", "192.168.0.3", "port_distribution", "2026-07-27T10:10:02+08:00"),
			evidenceItem("evidence-c", "192.168.0.3", "port_distribution", "2026-07-27T10:10:03+08:00"),
		},
		risks: []risk.Snapshot{
			riskSnapshot("192.168.0.1", "normal", 20, "2026-07-27T10:10:00+08:00"),
			riskSnapshot("192.168.0.2", "high", 75, "2026-07-27T10:10:01+08:00"),
			riskSnapshot("192.168.0.3", "confirmed", 90, "2026-07-27T10:10:02+08:00"),
			riskSnapshot("192.168.0.4", "suspicious", 45, "2026-07-27T10:10:03+08:00"),
		},
	})

	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "office-30", ReadOnly: true})
	var overview Overview
	getJSON(t, server, "/api/v1/overview", http.StatusOK, &overview)

	if overview.LatestShadowRun.RunID != "20260727-101000" {
		t.Fatalf("expected latest run 20260727-101000, got %s", overview.LatestShadowRun.RunID)
	}
	if overview.LevelCounts.Confirmed != 1 || overview.LevelCounts.High != 1 || overview.LevelCounts.Suspicious != 1 || overview.LevelCounts.Normal != 1 {
		t.Fatalf("unexpected level counts: %#v", overview.LevelCounts)
	}
	if overview.PendingReviews != 2 {
		t.Fatalf("expected high+confirmed pending reviews, got %d", overview.PendingReviews)
	}
	if overview.Throughput.Events != 10 || overview.Throughput.Evidence != 3 || overview.Throughput.Risks != 4 {
		t.Fatalf("unexpected throughput: %#v", overview.Throughput)
	}
	if len(overview.TopEvidence) != 2 || overview.TopEvidence[0].Type != "port_distribution" || overview.TopEvidence[0].Count != 2 {
		t.Fatalf("unexpected top evidence: %#v", overview.TopEvidence)
	}

	var runs struct {
		Runs []ShadowRun `json:"runs"`
	}
	getJSON(t, server, "/api/v1/shadow/runs", http.StatusOK, &runs)
	if len(runs.Runs) != 2 || runs.Runs[0].RunID != "20260727-101000" || runs.Runs[0].SensorID != "office-30" {
		t.Fatalf("unexpected runs: %#v", runs.Runs)
	}
	normalized := runs.Runs[0].Normalized.(map[string]any)
	if normalized["by_type"].(map[string]any)["device"].(float64) != 2 {
		t.Fatalf("expected merged device by_type in shadow run, got %#v", runs.Runs[0].Normalized)
	}
	zeekNormalized := runs.Runs[0].ZeekNormalized.(map[string]any)
	if zeekNormalized["by_type"].(map[string]any)["device"].(float64) != 2 {
		t.Fatalf("expected zeek device stats in shadow run, got %#v", runs.Runs[0].ZeekNormalized)
	}
	if runs.Runs[0].ZeekStatus != "ok" || runs.Runs[0].ZeekPrevOffset != 1000 || runs.Runs[0].ZeekNewOffset != 2000 {
		t.Fatalf("expected zeek status and offsets in shadow run, got %#v", runs.Runs[0])
	}

	var diagnostics struct {
		Diagnostics []ingest.Diagnostic `json:"diagnostics"`
	}
	getJSON(t, server, "/api/v1/ingest/diagnostics", http.StatusOK, &diagnostics)
	if len(diagnostics.Diagnostics) == 0 || diagnostics.Diagnostics[0].Details["zeek_status"] != "ok" {
		t.Fatalf("expected zeek status in ingest diagnostics, got %#v", diagnostics.Diagnostics)
	}
}

func TestRisksFilteringSortingPaginationAndSensor(t *testing.T) {
	shadowDir := t.TempDir()
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: "2026-07-27T10:10:00+08:00",
		risks: []risk.Snapshot{
			riskSnapshot("192.168.0.20", "high", 70, "2026-07-27T10:10:02+08:00"),
			riskSnapshot("192.168.0.10", "confirmed", 80, "2026-07-27T10:10:01+08:00"),
			riskSnapshot("192.168.0.30", "suspicious", 50, "2026-07-27T10:10:03+08:00"),
			riskSnapshot("192.168.0.40", "normal", 20, "2026-07-27T10:10:04+08:00"),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "test-sensor", ReadOnly: true})

	var page RiskListResponse
	getJSON(t, server, "/api/v1/risks?limit=2", http.StatusOK, &page)
	if len(page.Items) != 2 || page.Items[0].IP != "192.168.0.10" || page.Items[1].IP != "192.168.0.20" {
		t.Fatalf("unexpected sorted first page: %#v", page.Items)
	}
	if page.Page.Total != 4 || page.Page.NextCursor == nil || *page.Page.NextCursor != "2" {
		t.Fatalf("unexpected page metadata: %#v", page.Page)
	}

	getJSON(t, server, "/api/v1/risks?cursor=2&limit=2", http.StatusOK, &page)
	if len(page.Items) != 2 || page.Items[0].IP != "192.168.0.30" || page.Items[1].IP != "192.168.0.40" {
		t.Fatalf("unexpected second page: %#v", page.Items)
	}

	getJSON(t, server, "/api/v1/risks?level=high&q=70", http.StatusOK, &page)
	if len(page.Items) != 1 || page.Items[0].Level != "high" {
		t.Fatalf("expected one high risk matched by summary, got %#v", page.Items)
	}

	getJSON(t, server, "/api/v1/risks?sensor_id=other", http.StatusOK, &page)
	if page.Items == nil || len(page.Items) != 0 || page.Page.Total != 0 {
		t.Fatalf("expected empty page for mismatched sensor, got %#v", page)
	}

	getJSON(t, server, "/api/v1/risks?from=2026-07-27T10:10:03%2B08:00&to=2026-07-27T10:10:04%2B08:00", http.StatusOK, &page)
	if len(page.Items) != 2 {
		t.Fatalf("expected time filtered items, got %#v", page.Items)
	}
}

func TestIPDetailEndpointsSupportIPv6AndNormalFallback(t *testing.T) {
	shadowDir := t.TempDir()
	ipv6 := "240e:35a::abcd"
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: "2026-07-27T10:10:00+08:00",
		evidence: []evidence.Evidence{
			evidenceItem("evidence-v6-new", ipv6, "multi_user_agent", "2026-07-27T10:10:03+08:00"),
			evidenceItem("evidence-v6-old", ipv6, "port_distribution", "2026-07-27T10:10:01+08:00"),
		},
		risks: []risk.Snapshot{
			riskSnapshot(ipv6, "high", 72, "2026-07-27T10:10:03+08:00"),
		},
		events: []normalized.Event{
			normalizedEvent("event-old", ipv6, "2026-07-27T10:10:01+08:00"),
			normalizedEvent("event-other", "192.168.0.1", "2026-07-27T10:10:02+08:00"),
			normalizedEvent("event-new", ipv6, "2026-07-27T10:10:03+08:00"),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "office-30", ReadOnly: true})
	escaped := url.PathEscape(ipv6)

	var snapshot risk.Snapshot
	getJSON(t, server, "/api/v1/ips/"+escaped+"/risk", http.StatusOK, &snapshot)
	if snapshot.IP != ipv6 || snapshot.Level != "high" {
		t.Fatalf("unexpected ipv6 risk: %#v", snapshot)
	}

	var evidenceResponse struct {
		Evidence []evidence.Evidence `json:"evidence"`
	}
	getJSON(t, server, "/api/v1/ips/"+escaped+"/evidence", http.StatusOK, &evidenceResponse)
	if len(evidenceResponse.Evidence) != 2 || evidenceResponse.Evidence[0].EvidenceID != "evidence-v6-new" {
		t.Fatalf("unexpected evidence order: %#v", evidenceResponse.Evidence)
	}

	var eventsResponse struct {
		Events []normalized.Event `json:"events"`
	}
	getJSON(t, server, "/api/v1/ips/"+escaped+"/events?limit=1", http.StatusOK, &eventsResponse)
	if len(eventsResponse.Events) != 1 || eventsResponse.Events[0].EventID != "event-new" {
		t.Fatalf("unexpected event limit result: %#v", eventsResponse.Events)
	}

	var activity struct {
		IP         string `json:"ip"`
		EventCount int    `json:"event_count"`
		TopDomains []struct {
			Value string `json:"value"`
			Count int    `json:"count"`
		} `json:"top_domains"`
		TopHTTPHosts []struct {
			Value string `json:"value"`
			Count int    `json:"count"`
		} `json:"top_http_hosts"`
		TopUserAgents []struct {
			Value string `json:"value"`
			Count int    `json:"count"`
		} `json:"top_user_agents"`
		TopDstPorts []struct {
			Value string `json:"value"`
			Count int    `json:"count"`
		} `json:"top_dst_ports"`
		RecentAccesses []struct {
			TargetKind string `json:"target_kind"`
			Target     string `json:"target"`
		} `json:"recent_accesses"`
	}
	getJSON(t, server, "/api/v1/ips/"+escaped+"/activity?limit=2", http.StatusOK, &activity)
	if activity.IP != ipv6 || activity.EventCount != 2 {
		t.Fatalf("unexpected activity summary: %#v", activity)
	}
	if len(activity.TopDomains) == 0 || activity.TopDomains[0].Value != "example.test" {
		t.Fatalf("expected top domain example.test, got %#v", activity.TopDomains)
	}
	if len(activity.TopHTTPHosts) == 0 || activity.TopHTTPHosts[0].Value != "example.test" {
		t.Fatalf("expected http host example.test, got %#v", activity.TopHTTPHosts)
	}
	if len(activity.TopUserAgents) == 0 || activity.TopUserAgents[0].Value != "test-agent" {
		t.Fatalf("expected user agent, got %#v", activity.TopUserAgents)
	}
	if len(activity.TopDstPorts) == 0 || activity.TopDstPorts[0].Value != "80" {
		t.Fatalf("expected dst port 80, got %#v", activity.TopDstPorts)
	}
	if len(activity.RecentAccesses) != 2 || activity.RecentAccesses[0].Target == "" {
		t.Fatalf("unexpected recent accesses: %#v", activity.RecentAccesses)
	}

	getJSON(t, server, "/api/v1/ips/192.168.0.250/risk", http.StatusOK, &snapshot)
	if snapshot.IP != "192.168.0.250" || snapshot.Level != "normal" || len(snapshot.EvidenceIDs) != 0 {
		t.Fatalf("unexpected normal fallback: %#v", snapshot)
	}
}

func TestDeviceInventoryEndpointsExposeConservativeSignals(t *testing.T) {
	shadowDir := t.TempDir()
	ip := "192.168.10.55"
	now := time.Now().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	later := time.Now().Add(-5 * time.Minute).Format(time.RFC3339Nano)
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: now,
		events: []normalized.Event{
			httpEvent("event-device-http-a", ip, now, "portal.example.test", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
			httpEvent("event-device-http-b", ip, later, "m.example.test", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
			tlsEvent("event-device-tls-a", ip, later, "api.example.test", "chrome-ja3", "chrome-ja4"),
			tlsEvent("event-device-tls-b", ip, later, "api.example.test", "ios-ja3", "ios-ja4"),
		},
		risks: []risk.Snapshot{
			riskSnapshot(ip, "high", 75, later),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "test-sensor", ReadOnly: true})

	var inventory store.IPDeviceInventory
	getJSON(t, server, "/api/v1/ips/"+url.PathEscape(ip)+"/devices?window=1h", http.StatusOK, &inventory)
	if inventory.IP != ip || inventory.SuspectedDeviceCount < 2 || len(inventory.Devices) < 2 {
		t.Fatalf("expected multiple device candidates, got %#v", inventory)
	}
	if len(inventory.Conflicts) == 0 {
		t.Fatalf("expected signal conflicts, got %#v", inventory)
	}
	for _, signal := range inventory.Signals {
		if signal.Kind == "user_agent" && signal.Strength != "weak" {
			t.Fatalf("UA signal must remain weak: %#v", signal)
		}
	}

	var risks RiskListResponse
	getJSON(t, server, "/api/v1/risks", http.StatusOK, &risks)
	if len(risks.Items) != 1 || risks.Items[0].SuspectedDeviceCount < 2 || risks.Items[0].DeviceSummary == "" {
		t.Fatalf("expected enriched risk device summary, got %#v", risks.Items)
	}

	var signals struct {
		Items []store.DeviceSignal `json:"items"`
	}
	getJSON(t, server, "/api/v1/device-signals?ip="+url.QueryEscape(ip), http.StatusOK, &signals)
	if len(signals.Items) == 0 {
		t.Fatalf("expected device signals")
	}
}

func TestIdentityProfileEndpointsExposeAccountAndEndpointContext(t *testing.T) {
	shadowDir := t.TempDir()
	writeRun(t, shadowDir, "20260730-101000", testRun{
		startedAt: "2026-07-30T10:10:00+08:00",
		normalized: suricata.Stats{
			Read: 2, Emitted: 2, ByType: map[string]int{"identity": 2},
		},
		events: []normalized.Event{
			identityEvent("identity-a", "2026000123", "10.20.15.83", "aa:bb:cc:dd:ee:01", "Dorm-A-AP01", "sess-1", "2026-07-30T10:00:00+08:00"),
			identityEvent("identity-b", "2026000123", "10.20.16.44", "aa:bb:cc:dd:ee:01", "Dorm-A-AP01", "sess-1", "2026-07-30T10:05:00+08:00"),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "test-sensor", ReadOnly: true})

	var account store.AccountIdentityProfile
	getJSON(t, server, "/api/v1/accounts/2026000123/identity?limit=20", http.StatusOK, &account)
	if account.AccountID != "2026000123" || len(account.Endpoints) != 1 || len(account.IPHistory) != 2 || len(account.AccessHistory) != 2 {
		t.Fatalf("unexpected account identity profile: %#v", account)
	}
	if account.Endpoints[0].EndpointID != "mac:aa:bb:cc:dd:ee:01" || account.LastSeen == "" {
		t.Fatalf("expected endpoint and last seen in account profile: %#v", account)
	}

	var endpoint store.EndpointIdentityProfile
	getJSON(t, server, "/api/v1/endpoints/"+url.PathEscape("mac:aa:bb:cc:dd:ee:01")+"/identity?limit=20", http.StatusOK, &endpoint)
	if endpoint.EndpointID != "mac:aa:bb:cc:dd:ee:01" || len(endpoint.Accounts) != 1 || endpoint.Accounts[0] != "2026000123" || len(endpoint.IPHistory) != 2 {
		t.Fatalf("unexpected endpoint identity profile: %#v", endpoint)
	}

	var devices DeviceListResponse
	getJSON(t, server, "/api/v1/devices?limit=20", http.StatusOK, &devices)
	if len(devices.Items) != 1 || devices.Items[0].EndpointID != "mac:aa:bb:cc:dd:ee:01" || devices.Items[0].CurrentIP == "" || devices.Items[0].CurrentAccessID != "Dorm-A-AP01" {
		t.Fatalf("unexpected endpoint device list: %#v", devices)
	}

	var errResponse ErrorResponse
	getJSON(t, server, "/api/v1/accounts/missing/identity", http.StatusNotFound, &errResponse)
	if errResponse.Code != "account_identity_not_found" {
		t.Fatalf("unexpected missing account response: %#v", errResponse)
	}
}

func TestActivityOverviewAggregatesObservedDomainAndRiskIPs(t *testing.T) {
	shadowDir := t.TempDir()
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: "2026-07-27T10:10:00+08:00",
		risks: []risk.Snapshot{
			riskSnapshot("192.168.0.10", "high", 72, "2026-07-27T10:10:04+08:00"),
			riskSnapshot("192.168.0.20", "normal", 12, "2026-07-27T10:10:04+08:00"),
		},
		events: []normalized.Event{
			dnsEvent("event-dns", "192.168.0.10", "2026-07-27T10:10:01+08:00", "api.example.test"),
			httpEvent("event-http", "192.168.0.10", "2026-07-27T10:10:02+08:00", "api.example.test", "agent-a"),
			tlsEvent("event-tls", "192.168.0.20", "2026-07-27T10:10:03+08:00", "login.example.test", "chrome", "chrome-ja4"),
			flowEvent("event-flow", "192.168.0.30", "2026-07-27T10:10:04+08:00", "198.51.100.44", 8080),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "test-sensor", ReadOnly: true})

	var activity store.ActivityOverview
	getJSON(t, server, "/api/v1/activity/overview?window=10m", http.StatusOK, &activity)
	if activity.SensorID != "test-sensor" || activity.Window != "10m" {
		t.Fatalf("unexpected sensor/window: %#v", activity)
	}
	if activity.EventCount != 4 || activity.ActiveIPCount != 3 || activity.AccessObjectCount != 2 {
		t.Fatalf("unexpected overview counts: %#v", activity)
	}
	if len(activity.TopDomains) == 0 || activity.TopDomains[0].Value != "api.example.test" || activity.TopDomains[0].Count != 2 {
		t.Fatalf("expected merged DNS/HTTP top domain, got %#v", activity.TopDomains)
	}
	if len(activity.TopHTTPHosts) == 0 || activity.TopHTTPHosts[0].Value != "api.example.test" {
		t.Fatalf("expected top http host, got %#v", activity.TopHTTPHosts)
	}
	if len(activity.TopTLSSNI) == 0 || activity.TopTLSSNI[0].Value != "login.example.test" {
		t.Fatalf("expected top tls sni, got %#v", activity.TopTLSSNI)
	}
	if len(activity.TopUserAgents) == 0 || activity.TopUserAgents[0].Value != "agent-a" {
		t.Fatalf("expected user agent, got %#v", activity.TopUserAgents)
	}
	if len(activity.TopTLSFingerprints) != 2 {
		t.Fatalf("expected ja3/ja4 fingerprints, got %#v", activity.TopTLSFingerprints)
	}
	if !hasActivityValue(activity.TopDstPorts, "443") {
		t.Fatalf("expected dst port ranking, got %#v", activity.TopDstPorts)
	}
	if len(activity.TopSourceIPs) == 0 || activity.TopSourceIPs[0].Value != "192.168.0.10" {
		t.Fatalf("expected top source ip, got %#v", activity.TopSourceIPs)
	}
	if activity.ActiveRiskIPCount != 1 || len(activity.TopActiveRiskIPs) != 1 || activity.TopActiveRiskIPs[0].IP != "192.168.0.10" {
		t.Fatalf("unexpected active risk ips: %#v", activity.TopActiveRiskIPs)
	}
	if strings.Contains(activity.TopActiveRiskIPs[0].IP, "/") {
		t.Fatalf("risk ip should not contain CIDR suffix: %s", activity.TopActiveRiskIPs[0].IP)
	}

	var empty store.ActivityOverview
	getJSON(t, server, "/api/v1/activity/overview?sensor_id=other&window=1h", http.StatusOK, &empty)
	if empty.EventTypeCounts == nil || empty.TopDomains == nil || empty.TopActiveRiskIPs == nil || empty.EventCount != 0 {
		t.Fatalf("expected empty arrays for mismatched sensor, got %#v", empty)
	}

	var errResponse ErrorResponse
	getJSON(t, server, "/api/v1/activity/overview?window=30m", http.StatusBadRequest, &errResponse)
	if errResponse.Code != "bad_activity_window" {
		t.Fatalf("unexpected error response: %#v", errResponse)
	}
}

func TestProxyReviewsExposeSevenDayAccountEndpointAggregation(t *testing.T) {
	shadowDir := t.TempDir()
	ip := "10.20.15.83"
	identity := identityEvent("identity-proxy", "2026000123", ip, "aa:bb:cc:dd:ee:01", "Dorm-A-AP01", "sess-proxy", "2026-08-20T10:00:00Z")
	tls := tlsEvent("tls-proxy", ip, "2026-08-20T10:05:00Z", "student-vpn.example.test", "vpn-ja3", "vpn-ja4")
	tls.Flow["start"] = "2026-08-20T10:01:00Z"
	tls.Flow["end"] = "2026-08-20T10:06:00Z"
	alert := baseEvent("alert-proxy", ip, "2026-08-20T10:07:00Z", "alert")
	alert.Flow["dst_port"] = 1194
	alert.Flow["proto"] = "udp"
	alert.Payload = map[string]any{
		"signature": "ET POLICY OpenVPN Client Connection",
		"category":  "Potential Corporate Privacy Violation",
		"action":    "allowed",
		"severity":  2,
	}
	writeRun(t, shadowDir, "20260820-101000", testRun{
		startedAt: "2026-08-20T10:10:00Z",
		events:    []normalized.Event{identity, tls, alert},
		risks:     []risk.Snapshot{riskSnapshot(ip, "confirmed", 88, "2026-08-20T10:07:00Z")},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "test-sensor", ReadOnly: true})

	var response store.ProxyReviewResponse
	getJSON(t, server, "/api/v1/proxy-reviews?window=7d", http.StatusOK, &response)
	if response.Window != "7d" || response.CaseCount != 1 || response.HighConfidenceCount != 1 {
		t.Fatalf("unexpected proxy review overview: %#v", response)
	}
	item := response.Items[0]
	if item.AccountID != "2026000123" || item.EndpointID != "mac:aa:bb:cc:dd:ee:01" || len(item.RuleMatches) != 1 || item.DurationSeconds != 360 {
		t.Fatalf("unexpected proxy review item: %#v", item)
	}

	var errResponse ErrorResponse
	getJSON(t, server, "/api/v1/proxy-reviews?window=30d", http.StatusBadRequest, &errResponse)
	if errResponse.Code != "bad_proxy_review_window" {
		t.Fatalf("unexpected bad window response: %#v", errResponse)
	}
}

func TestReadOnlySessionLabelsAndRulesReload(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "office-30", ReadOnly: true})

	var session Session
	getJSON(t, server, "/api/v1/session", http.StatusOK, &session)
	if session.User.ID != "shadow-viewer" || session.User.Name != "影子观测只读用户" {
		t.Fatalf("unexpected read-only user: %#v", session.User)
	}
	for _, permission := range session.Permissions {
		if permission == "labels:create" || permission == "rules:reload" {
			t.Fatalf("read-only session leaked mutating permission: %#v", session.Permissions)
		}
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/labels", strings.NewReader(`{}`))
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected labels 403, got %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/mac%3Aaa%3Abb%3Acc%3Add%3Aee%3A01/registration", strings.NewReader(`{}`))
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected endpoint registration 403, got %d", recorder.Code)
	}

	var reload RuleReloadResult
	postJSON(t, server, "/api/v1/rules/reload", http.StatusAccepted, &reload)
	if reload.Status != "disabled" || reload.Mode != "shadow" {
		t.Fatalf("unexpected reload result: %#v", reload)
	}
}

func TestCreateLabelWritesAuditInNonReadOnlyMode(t *testing.T) {
	shadowDir := t.TempDir()
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: "2026-07-27T10:10:00+08:00",
		risks: []risk.Snapshot{
			riskSnapshot("10.0.0.8", "high", 72, "2026-07-27T10:10:00+08:00"),
			riskSnapshot("10.0.0.9", "confirmed", 88, "2026-07-27T10:10:01+08:00"),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "office-30", ReadOnly: false})

	var session Session
	getJSON(t, server, "/api/v1/session", http.StatusOK, &session)
	if session.User.ID != "shadow-operator" || session.User.Name != "影子运营复核员" {
		t.Fatalf("unexpected review operator: %#v", session.User)
	}
	if !hasPermission(session.Permissions, "labels:create") {
		t.Fatalf("expected labels:create permission, got %#v", session.Permissions)
	}

	var label store.Label
	postJSONBody(t, server, "/api/v1/labels", http.StatusCreated, &label, `{
		"target_type":"ip",
		"target_id":"10.0.0.8",
		"label":"false_positive",
		"reason":"人工复核确认是测试设备",
		"evidence_ids":["evidence-1"]
	}`)
	if label.LabelID == "" || label.CreatedBy == "" || label.TargetID != "10.0.0.8" {
		t.Fatalf("unexpected created label: %#v", label)
	}

	var audit struct {
		Logs []AuditLog `json:"logs"`
	}
	getJSON(t, server, "/api/v1/audit-logs", http.StatusOK, &audit)
	if len(audit.Logs) == 0 || audit.Logs[0].Action != "labels.create" {
		t.Fatalf("expected labels.create audit log, got %#v", audit.Logs)
	}

	var snapshot risk.Snapshot
	getJSON(t, server, "/api/v1/ips/10.0.0.8/risk", http.StatusOK, &snapshot)
	if snapshot.ReviewStatus != "false_positive" || snapshot.ReviewReason != "人工复核确认是测试设备" || snapshot.ReviewedBy == "" || snapshot.ReviewedAt == "" {
		t.Fatalf("expected risk detail to include latest review label, got %#v", snapshot)
	}
	if snapshot.Level != "normal" || snapshot.Score > 20 || snapshot.RawLevel != "high" || snapshot.RawScore != 72 || len(snapshot.NegativeEvidence) != 1 || snapshot.NegativeEvidence[0].Type != "test_device" {
		t.Fatalf("expected false_positive review to apply negative evidence while preserving raw risk, got %#v", snapshot)
	}

	var page RiskListResponse
	getJSON(t, server, "/api/v1/risks", http.StatusOK, &page)
	if len(page.Items) < 2 || page.Items[0].ReviewStatus == "" {
		t.Fatalf("expected risk list items to include review status, got %#v", page.Items)
	}
	getJSON(t, server, "/api/v1/risks?level=high", http.StatusOK, &page)
	for _, item := range page.Items {
		if item.IP == "10.0.0.8" {
			t.Fatalf("expected downgraded false-positive risk to be excluded from high list, got %#v", page.Items)
		}
	}

	var overview Overview
	getJSON(t, server, "/api/v1/overview", http.StatusOK, &overview)
	if overview.PendingReviews != 1 {
		t.Fatalf("expected reviewed high risk to be excluded from pending reviews, got %d", overview.PendingReviews)
	}
}

func TestCreateLabelRequiresEvidenceIDs(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "office-30", ReadOnly: false})

	var errResponse ErrorResponse
	postJSONBody(t, server, "/api/v1/labels", http.StatusBadRequest, &errResponse, `{
		"target_type":"ip",
		"target_id":"10.0.0.8",
		"label":"needs_more_data",
		"reason":"缺少证据 ID",
		"evidence_ids":[]
	}`)
	if errResponse.Code != "bad_label_request" || !strings.Contains(errResponse.Message, "evidence_ids") {
		t.Fatalf("expected evidence_ids validation error, got %#v", errResponse)
	}

	var audit struct {
		Logs []AuditLog `json:"logs"`
	}
	getJSON(t, server, "/api/v1/audit-logs", http.StatusOK, &audit)
	for _, log := range audit.Logs {
		if log.Action == "labels.create" {
			t.Fatalf("invalid label should not create audit log, got %#v", audit.Logs)
		}
	}
}

func TestUpdateEndpointRegistrationWritesAuditAndProfile(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "office-30", ReadOnly: false})

	var session Session
	getJSON(t, server, "/api/v1/session", http.StatusOK, &session)
	if !hasPermission(session.Permissions, "endpoints:write") {
		t.Fatalf("expected endpoints:write permission, got %#v", session.Permissions)
	}

	endpointID := "mac:aa:bb:cc:dd:ee:01"
	var endpoint store.EndpointEntity
	postJSONBody(t, server, "/api/v1/endpoints/"+url.PathEscape(endpointID)+"/registration", http.StatusOK, &endpoint, `{
		"registration_status":"registered",
		"owner_account":"2026000123",
		"owner_name":"张三",
		"owner_department":"计算机学院",
		"asset_tag":"LAPTOP-001",
		"registration_note":"人工登记样本"
	}`)
	if endpoint.EndpointID != endpointID || endpoint.RegistrationStatus != "registered" || endpoint.OwnerAccount != "2026000123" || endpoint.MergeStatus != "active" {
		t.Fatalf("unexpected endpoint registration response: %#v", endpoint)
	}

	var profile store.EndpointIdentityProfile
	getJSON(t, server, "/api/v1/endpoints/"+url.PathEscape(endpointID)+"/identity", http.StatusOK, &profile)
	if profile.Endpoint.RegistrationStatus != "registered" || profile.Endpoint.OwnerName != "张三" || profile.Endpoint.AssetTag != "LAPTOP-001" {
		t.Fatalf("expected endpoint identity to include registration metadata, got %#v", profile.Endpoint)
	}

	var audit struct {
		Logs []AuditLog `json:"logs"`
	}
	getJSON(t, server, "/api/v1/audit-logs", http.StatusOK, &audit)
	if len(audit.Logs) == 0 || audit.Logs[0].Action != "endpoints.registration.update" {
		t.Fatalf("expected endpoints.registration.update audit log, got %#v", audit.Logs)
	}
}

func TestAPICORSAllowsLocalDevOrigins(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "office-30", ReadOnly: true})

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/activity/overview", nil)
	preflight.Header.Set("Origin", "http://localhost:5173")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, preflight)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected CORS preflight 204, got %d with body %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("unexpected allow origin: %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "OPTIONS") || !strings.Contains(got, "GET") {
		t.Fatalf("unexpected allow methods: %q", got)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Origin", "http://127.0.0.1:5173")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected session 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:5173" {
		t.Fatalf("unexpected allow origin on GET: %q", got)
	}
}

func hasPermission(permissions []string, expected string) bool {
	for _, permission := range permissions {
		if permission == expected {
			return true
		}
	}
	return false
}

func TestAPICORSRejectsUnknownPreflightOrigin(t *testing.T) {
	server := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "office-30", ReadOnly: true})

	request := httptest.NewRequest(http.MethodOptions, "/api/v1/activity/overview", nil)
	request.Header.Set("Origin", "https://example.invalid")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden preflight, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected allow origin for forbidden origin: %q", got)
	}
}

func TestIngestAndEventEndpoints(t *testing.T) {
	shadowDir := t.TempDir()
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: "2026-07-27T10:10:00+08:00",
		normalized: suricata.Stats{
			Read: 4, Emitted: 3, Skipped: 1, Malformed: 0, ByType: map[string]int{"dns": 2, "http": 1},
		},
		events: []normalized.Event{
			normalizedEvent("event-dns-1", "192.168.0.8", "2026-07-27T10:10:01+08:00"),
			normalizedEvent("event-http-1", "192.168.0.9", "2026-07-27T10:10:02+08:00"),
			normalizedEvent("event-dns-2", "192.168.0.8", "2026-07-27T10:10:03+08:00"),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "office-30", ReadOnly: true})

	var status struct {
		SensorID          string         `json:"sensor_id"`
		Healthy           bool           `json:"healthy"`
		LastCounters      map[string]int `json:"last_counters"`
		LastEventTypeDist map[string]int `json:"last_event_type_dist"`
	}
	getJSON(t, server, "/api/v1/ingest/status", http.StatusOK, &status)
	if status.SensorID != "office-30" || !status.Healthy || status.LastCounters["emitted"] != 3 || status.LastEventTypeDist["dns"] != 2 {
		t.Fatalf("unexpected ingest status: %#v", status)
	}

	var diagnostics struct {
		Diagnostics []map[string]any `json:"diagnostics"`
	}
	getJSON(t, server, "/api/v1/ingest/diagnostics", http.StatusOK, &diagnostics)
	if len(diagnostics.Diagnostics) != 1 || diagnostics.Diagnostics[0]["raw_ref"] == nil {
		t.Fatalf("unexpected diagnostics: %#v", diagnostics.Diagnostics)
	}

	var eventTypes struct {
		EventTypes []map[string]any `json:"event_types"`
	}
	getJSON(t, server, "/api/v1/ingest/event-types", http.StatusOK, &eventTypes)
	if len(eventTypes.EventTypes) != 2 || eventTypes.EventTypes[0]["type"] != "dns" {
		t.Fatalf("unexpected event type distribution: %#v", eventTypes.EventTypes)
	}

	var eventsResponse struct {
		Events []normalized.Event `json:"events"`
		Page   Page               `json:"page"`
	}
	getJSON(t, server, "/api/v1/events?q=192.168.0.8&limit=2", http.StatusOK, &eventsResponse)
	if len(eventsResponse.Events) != 2 {
		t.Fatalf("expected two event samples for ip, got %#v", eventsResponse.Events)
	}
	if eventsResponse.Page.Total != 2 || eventsResponse.Page.Limit != 2 {
		t.Fatalf("unexpected events page: %#v", eventsResponse.Page)
	}

	var event normalized.Event
	getJSON(t, server, "/api/v1/events/event-http-1", http.StatusOK, &event)
	if event.EventID != "event-http-1" {
		t.Fatalf("unexpected event lookup: %#v", event)
	}
}

func TestEventSearchFiltersAndPagination(t *testing.T) {
	shadowDir := t.TempDir()
	writeRun(t, shadowDir, "20260727-101000", testRun{
		startedAt: "2026-07-27T10:10:00+08:00",
		events: []normalized.Event{
			dnsEvent("event-dns-api", "192.168.0.8", "2026-07-27T10:10:01+08:00", "api.example.test"),
			httpEvent("event-http-ua", "192.168.0.8", "2026-07-27T10:10:02+08:00", "portal.example.test", "desktop-agent"),
			tlsEvent("event-tls-sni", "192.168.0.9", "2026-07-27T10:10:03+08:00", "api.example.test", "chrome", "chrome-ja4"),
			flowEvent("event-flow", "192.168.0.10", "2026-07-27T10:10:04+08:00", "198.51.100.44", 8080),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "test-sensor", ReadOnly: true})

	var response EventListResponse
	getJSON(t, server, "/api/v1/events?domain=api.example.test&limit=1", http.StatusOK, &response)
	if len(response.Events) != 1 || response.Page.Total != 2 || response.Page.NextCursor == nil {
		t.Fatalf("expected first domain page with next cursor, got %#v", response)
	}
	nextCursor := *response.Page.NextCursor
	response = EventListResponse{}
	getJSON(t, server, "/api/v1/events?domain=api.example.test&limit=1&cursor="+nextCursor, http.StatusOK, &response)
	if len(response.Events) != 1 || response.Page.NextCursor != nil {
		t.Fatalf("expected second domain page without next cursor, got %#v", response)
	}

	response = EventListResponse{}
	getJSON(t, server, "/api/v1/events?user_agent=desktop-agent", http.StatusOK, &response)
	if len(response.Events) != 1 || response.Events[0].EventID != "event-http-ua" {
		t.Fatalf("unexpected user agent filter: %#v", response.Events)
	}
	response = EventListResponse{}
	getJSON(t, server, "/api/v1/events?fingerprint=chrome-ja4", http.StatusOK, &response)
	if len(response.Events) != 1 || response.Events[0].EventID != "event-tls-sni" {
		t.Fatalf("unexpected fingerprint filter: %#v", response.Events)
	}
	response = EventListResponse{}
	getJSON(t, server, "/api/v1/events?fingerprint=ja4:chrome-ja4", http.StatusOK, &response)
	if len(response.Events) != 1 || response.Events[0].EventID != "event-tls-sni" {
		t.Fatalf("unexpected prefixed fingerprint filter: %#v", response.Events)
	}
	response = EventListResponse{}
	getJSON(t, server, "/api/v1/events?dst_ip=198.51.100.44&port=8080&proto=tcp", http.StatusOK, &response)
	if len(response.Events) != 1 || response.Events[0].EventID != "event-flow" {
		t.Fatalf("unexpected dst/port/proto filter: %#v", response.Events)
	}
	response = EventListResponse{}
	getJSON(t, server, "/api/v1/events?from=2026-07-27T10:10:03%2B08:00", http.StatusOK, &response)
	if response.Page.Total != 2 {
		t.Fatalf("unexpected time filter result: %#v", response)
	}

	var errResponse ErrorResponse
	getJSON(t, server, "/api/v1/events?port=99999", http.StatusBadRequest, &errResponse)
	if errResponse.Code != "bad_port" {
		t.Fatalf("unexpected bad port response: %#v", errResponse)
	}
}

func TestDPIEndpointsFromFileStore(t *testing.T) {
	shadowDir := t.TempDir()
	now := time.Now().Add(-5 * time.Minute).Format(time.RFC3339)
	later := time.Now().Add(-4 * time.Minute).Format(time.RFC3339)
	writeRun(t, shadowDir, "20260728-101000", testRun{
		startedAt: now,
		evidence: []evidence.Evidence{
			evidenceItem("evidence-dpi", "192.168.10.8", "multi_user_agent", later),
		},
		risks: []risk.Snapshot{
			riskSnapshot("192.168.10.8", "high", 70, later),
		},
		events: []normalized.Event{
			httpEvent("event-http-dpi-a", "192.168.10.8", now, "portal.example.test", "desktop-agent"),
			httpEvent("event-http-dpi-b", "192.168.10.8", later, "portal.example.test", "mobile-agent"),
			tlsEvent("event-tls-dpi", "192.168.10.8", later, "api.example.test", "chrome-ja3", "chrome-ja4"),
			dnsEvent("event-dns-dpi", "192.168.10.9", later, "api.example.test"),
			flowEvent("event-flow-dpi", "192.168.10.10", later, "198.51.100.44", 8080),
		},
	})
	server := NewServer(Options{ShadowDir: shadowDir, SensorID: "test-sensor", ReadOnly: true})

	var overview store.DPIOverview
	getJSON(t, server, "/api/v1/dpi/overview?sensor_id=test-sensor&window=1h", http.StatusOK, &overview)
	if overview.EventCount != 5 || overview.ActiveIPCount != 3 || overview.ProtocolFlowCount == 0 {
		t.Fatalf("unexpected dpi overview: %#v", overview)
	}

	var trends struct {
		Points []store.DPITrendPoint `json:"points"`
	}
	getJSON(t, server, "/api/v1/dpi/trends?sensor_id=test-sensor&window=1h", http.StatusOK, &trends)
	if len(trends.Points) == 0 || !trends.Points[0].Estimated {
		t.Fatalf("expected estimated trend points, got %#v", trends.Points)
	}

	var protocols struct {
		Items []store.DPIProtocolFlow `json:"items"`
	}
	getJSON(t, server, "/api/v1/dpi/protocol-flows?sensor_id=test-sensor&window=1h", http.StatusOK, &protocols)
	if len(protocols.Items) == 0 || protocols.Items[0].EventCount == 0 {
		t.Fatalf("unexpected protocol flows: %#v", protocols.Items)
	}

	var conflicts struct {
		Items []store.DPIFingerprintConflict `json:"items"`
	}
	getJSON(t, server, "/api/v1/dpi/fingerprint-conflicts?sensor_id=test-sensor&window=1h", http.StatusOK, &conflicts)
	if len(conflicts.Items) == 0 || conflicts.Items[0].IP != "192.168.10.8" {
		t.Fatalf("expected UA conflict for 192.168.10.8, got %#v", conflicts.Items)
	}

	var flows store.DPIFlowPage
	getJSON(t, server, "/api/v1/dpi/flows?sensor_id=test-sensor&domain=api.example.test&window=1h", http.StatusOK, &flows)
	if flows.Page.Total != 2 || len(flows.Items) == 0 {
		t.Fatalf("unexpected dpi flow page: %#v", flows)
	}
	if flows.Items[0].PayloadSummary == "" || flows.Items[0].FlowID == "" {
		t.Fatalf("expected standardized flow summary and id, got %#v", flows.Items[0])
	}

	var detail store.DPIFlowDetail
	getJSON(t, server, "/api/v1/dpi/flows/event-tls-dpi", http.StatusOK, &detail)
	if detail.Flow.EventID != "event-tls-dpi" || detail.Risk.IP != "192.168.10.8" || len(detail.Evidence) != 1 {
		t.Fatalf("unexpected dpi flow detail: %#v", detail)
	}

	escaped := url.PathEscape("192.168.10.8")
	flows = store.DPIFlowPage{}
	getJSON(t, server, "/api/v1/dpi/ips/"+escaped+"/flows?window=1h", http.StatusOK, &flows)
	if flows.Page.Total != 3 {
		t.Fatalf("expected ip-scoped dpi flows, got %#v", flows)
	}
}

type testRun struct {
	startedAt      string
	normalized     suricata.Stats
	zeekNormalized zeek.Stats
	zeekStatus     string
	zeekReason     string
	zeekPrevOffset int64
	zeekNewOffset  int64
	zeekTruncated  bool
	evidence       []evidence.Evidence
	risks          []risk.Snapshot
	events         []normalized.Event
}

func writeRun(t *testing.T, shadowDir string, runID string, run testRun) {
	t.Helper()
	runDir := filepath.Join(shadowDir, "runs", runID)
	if err := os.MkdirAll(runDir, 0755); err != nil {
		t.Fatalf("create run dir: %v", err)
	}
	finishedAt := run.startedAt
	if finishedAt == "" {
		finishedAt = "2026-07-27T10:10:00+08:00"
	}
	if run.normalized.Read == 0 && run.normalized.Emitted == 0 {
		run.normalized = suricata.Stats{Read: len(run.events), Emitted: len(run.events), ByType: map[string]int{}}
	}
	summary := shadow.RunSummary{
		StartedAt:      run.startedAt,
		FinishedAt:     finishedAt,
		RunDir:         runDir,
		PreviousOffset: 100,
		NewOffset:      200,
		Truncated:      false,
		Normalized:     run.normalized,
		ZeekNormalized: run.zeekNormalized,
		ZeekStatus:     run.zeekStatus,
		ZeekReason:     run.zeekReason,
		ZeekPrevOffset: run.zeekPrevOffset,
		ZeekNewOffset:  run.zeekNewOffset,
		ZeekTruncated:  run.zeekTruncated,
		EvidenceCount:  len(run.evidence),
		RiskCount:      len(run.risks),
		RiskListCount:  len(run.risks),
	}
	mustWriteJSON(t, filepath.Join(runDir, "run-summary.json"), summary)
	mustWriteJSON(t, filepath.Join(runDir, "risk-snapshots.json"), risk.BatchResult{Snapshots: run.risks})
	mustWriteJSON(t, filepath.Join(runDir, "evidence.json"), evidence.Result{Evidence: run.evidence})
	writeEvents(t, filepath.Join(runDir, "normalized.jsonl"), run.events)
}

func riskSnapshot(ip, level string, score int, updatedAt string) risk.Snapshot {
	return risk.Snapshot{
		IP:                ip,
		Score:             score,
		Level:             level,
		Confidence:        0.8,
		Window:            "10m0s",
		EvidenceIDs:       []string{"evidence-" + ip},
		Summary:           "summary score " + strconv.Itoa(score),
		RecommendedAction: "shadow_watch",
		UpdatedAt:         updatedAt,
	}
}

func evidenceItem(id, ip, evidenceType, createdAt string) evidence.Evidence {
	return evidence.Evidence{
		EvidenceID: id,
		IP:         ip,
		Type:       evidenceType,
		Window:     "10m0s",
		Score:      30,
		Confidence: 0.8,
		Severity:   "medium",
		Reason:     "test evidence",
		Samples:    []string{"sample"},
		CreatedAt:  createdAt,
	}
}

func normalizedEvent(id, ip, timestamp string) normalized.Event {
	return httpEvent(id, ip, timestamp, "example.test", "test-agent")
}

func dnsEvent(id, ip, timestamp, query string) normalized.Event {
	event := baseEvent(id, ip, timestamp, "dns")
	event.Flow["dst_ip"] = "198.51.100.53"
	event.Flow["dst_port"] = 53
	event.Flow["proto"] = "udp"
	event.Payload = map[string]any{"query": query}
	return event
}

func httpEvent(id, ip, timestamp, host, userAgent string) normalized.Event {
	event := baseEvent(id, ip, timestamp, "http")
	event.Flow["dst_ip"] = "198.51.100.80"
	event.Flow["dst_port"] = 80
	event.Flow["proto"] = "tcp"
	event.Payload = map[string]any{"host": host, "url": "/index.html", "user_agent": userAgent, "method": "GET"}
	return event
}

func tlsEvent(id, ip, timestamp, sni, ja3, ja4 string) normalized.Event {
	event := baseEvent(id, ip, timestamp, "tls")
	event.Flow["dst_ip"] = "198.51.100.443"
	event.Flow["dst_port"] = 443
	event.Flow["proto"] = "tcp"
	event.Payload = map[string]any{"sni": sni, "ja3": ja3, "ja4": ja4}
	return event
}

func flowEvent(id, ip, timestamp, dstIP string, dstPort int) normalized.Event {
	event := baseEvent(id, ip, timestamp, "flow")
	event.Flow["dst_ip"] = dstIP
	event.Flow["dst_port"] = dstPort
	event.Flow["proto"] = "tcp"
	event.Payload = map[string]any{}
	return event
}

func baseEvent(id, ip, timestamp, eventType string) normalized.Event {
	return normalized.Event{
		SchemaVersion: "v1",
		EventID:       id,
		Source:        "suricata",
		Type:          eventType,
		Timestamp:     timestamp,
		Observer:      map[string]any{"sensor_id": "test-sensor"},
		Subject:       map[string]any{"ip": ip},
		Flow:          map[string]any{"src_ip": ip, "dst_ip": "198.51.100.1", "dst_port": 80},
		Payload:       map[string]any{},
		Confidence:    1,
		RawRef:        map[string]any{"backend": "suricata", "line_offset": 1},
	}
}

func identityEvent(id, accountID, ip, mac, accessID, sessionID, timestamp string) normalized.Event {
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         id,
		Source:          "radius",
		SourceEventType: "identity",
		Type:            "identity",
		Timestamp:       timestamp,
		Observer:        map[string]any{"sensor_id": "test-sensor"},
		Subject: map[string]any{
			"ip":                  ip,
			"account_id":          accountID,
			"user_id":             accountID,
			"endpoint_id":         "mac:" + mac,
			"mac":                 mac,
			"access_id":           accessID,
			"entity_role":         "endpoint",
			"identity_confidence": 0.92,
		},
		Flow: map[string]any{"src_ip": ip, "dst_ip": "0.0.0.0", "proto": "other", "direction": "unknown"},
		Payload: map[string]any{
			"origin":     "radius",
			"session_id": sessionID,
			"ap":         accessID,
			"vlan":       "108",
		},
		Confidence: 0.92,
		RawRef:     map[string]any{"backend": "radius"},
	}
}

func hasActivityValue(items []store.ActivityCount, value string) bool {
	for _, item := range items {
		if item.Value == value {
			return true
		}
	}
	return false
}

func mustWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		t.Fatalf("write json: %v", err)
	}
}

func writeEvents(t *testing.T, path string, events []normalized.Event) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create events: %v", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			t.Fatalf("write event: %v", err)
		}
	}
}

func getJSON(t *testing.T, server *Server, path string, status int, target any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	decodeResponse(t, recorder, status, target)
}

func postJSON(t *testing.T, server *Server, path string, status int, target any) {
	t.Helper()
	postJSONBody(t, server, path, status, target, `{}`)
}

func postJSONBody(t *testing.T, server *Server, path string, status int, target any, body string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	decodeResponse(t, recorder, status, target)
}

func decodeResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, target any) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("expected status %d, got %d with body %s", status, recorder.Code, recorder.Body.String())
	}
	if err := json.NewDecoder(recorder.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, recorder.Body.String())
	}
}
