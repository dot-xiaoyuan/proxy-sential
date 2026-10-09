package store

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"testing"
)

func TestProxyReviewConfidenceAgreesWithRuleMetadata(t *testing.T) {
	for _, tc := range []struct{ name, signature, confidence, want string }{
		{"socks-hint", "PROXY_SENTINEL SOCKS5 no-auth greeting hint", "medium", "medium"},
		{"connect-hint", "PROXY_SENTINEL HTTP CONNECT proxy hint", "medium", "medium"},
		{"legacy-no-declaration", "ET POLICY OpenVPN Client Connection", "", "medium"},
		{"low-hint", "SOCKS5 hint", "low", "low"},
		{"high-wireguard", "PROXY_SENTINEL WireGuard handshake", "high", "high"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"signature": tc.signature}
			if tc.confidence != "" {
				payload["metadata"] = map[string]any{"proxy_sentinel_confidence": []any{tc.confidence}}
			}
			event := proxyTestEvent("alert", "alert", "2026-10-01T00:00:00Z", map[string]any{"ip": "192.0.2.70"}, nil, payload)
			response := BuildProxyReviewResponse("office-30", "7d", []normalized.Event{event}, nil)
			if len(response.Items) != 1 || response.Items[0].ConfidenceLevel != tc.want || (response.HighConfidenceCount == 1) != (tc.want == "high") || response.Items[0].AlertCount != 1 || len(response.Items[0].RuleMatches) != 1 {
				t.Fatalf("hint presented as stronger proof: %+v", response)
			}
		})
	}
}

func TestProxyConfidenceFixtureAcrossEvidenceRiskAndReview(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "proxy-review", "hint-boundaries.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	decoded := []normalized.Event{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var event normalized.Event
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, event)
	}
	analysis, err := evidence.Analyze(bytes.NewReader(raw), evidence.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Evidence) != 4 {
		t.Fatalf("ordinary words/campus VPN produced proxy evidence: %+v", analysis.Evidence)
	}
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := risk.Batch(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Snapshots) != 4 {
		t.Fatalf("risk path dropped explicit fixture evidence: %+v", batch.Snapshots)
	}
	for _, snapshot := range batch.Snapshots {
		if snapshot.IP == "192.0.2.1" || snapshot.IP == "192.0.2.2" || snapshot.IP == "192.0.2.3" {
			t.Fatalf("benign fixture became risk: %+v", snapshot)
		}
		if snapshot.IP != "192.0.2.5" && snapshot.DetectionBasis != "behavioral_only" {
			t.Fatalf("weak hint became explicit proof: %+v", snapshot)
		}
	}
	response := BuildProxyReviewResponse("replay-30", "7d", decoded, ProxyReviewRiskMap(batch.Snapshots))
	if response.EventCount != 6 || response.CaseCount != 6 || response.HighConfidenceCount != 1 {
		t.Fatalf("wrong review inclusion/confidence: %+v", response)
	}
	want := map[string]string{"192.0.2.1": "low", "192.0.2.2": "low", "192.0.2.4": "medium", "192.0.2.5": "high", "192.0.2.6": "low", "192.0.2.7": "medium"}
	for _, item := range response.Items {
		if want[item.IP] != item.ConfidenceLevel {
			t.Errorf("review disagrees with evidence for %s: %s", item.IP, item.ConfidenceLevel)
		}
		if item.IP == "192.0.2.6" && (item.RiskScore > 20 || item.ConfidenceLevel != "low") {
			t.Fatalf("low clue strengthened by risk enrichment: %+v", item)
		}
	}
}

func TestProxyReviewOrdinaryWordsDoNotBecomeProxyClues(t *testing.T) {
	for _, value := range []string{"store.apple.com", "history.example.test", "greeting.example.test", "directory.example.test", "vpn.henu.edu.cn", "webvpn.campus.edu.cn", "sslvpn.campus.edu.cn"} {
		t.Run(value, func(t *testing.T) {
			event := proxyTestEvent("tls", "tls", "2026-10-01T00:00:00Z", map[string]any{"ip": "192.0.2.70"}, nil, map[string]any{"sni": value})
			response := BuildProxyReviewResponse("office-30", "7d", []normalized.Event{event}, nil)
			if len(response.Items) != 1 || response.Items[0].ConfidenceLevel != "low" {
				t.Fatalf("ordinary TLS upgraded to proxy clue: %+v", response)
			}
		})
	}
}
