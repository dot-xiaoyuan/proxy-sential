package store

import (
	"encoding/json"
	"testing"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func TestProxyReviewSeparatesCueAndRiskConfidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		risks map[string]risk.Snapshot
		want  any
	}{
		{"current_estimate", map[string]risk.Snapshot{"192.0.2.82": {IP: "192.0.2.82", Score: 100, Level: "high", Confidence: .81}}, .81},
		{"zero_estimate", map[string]risk.Snapshot{"192.0.2.82": {IP: "192.0.2.82", Confidence: 0}}, 0.},
		{"missing_estimate", nil, nil},
		{"different_subject", map[string]risk.Snapshot{"192.0.2.82": {IP: "192.0.2.82", SubjectType: "account", SubjectID: "other", AccountID: "other", Confidence: .99}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := proxyTestEvent("high-cue", "alert", "2026-10-01T01:00:00Z", map[string]any{"ip": "192.0.2.82"}, nil, map[string]any{"signature": "PROXY_SENTINEL WireGuard handshake initiation", "metadata": map[string]any{"proxy_sentinel_confidence": "high"}})
			result := BuildProxyReviewResponse("test", "10m", []normalized.Event{e}, tc.risks)
			if len(result.Items) != 1 || result.Items[0].ConfidenceLevel != "high" {
				t.Fatal("protocol cue grade lost")
			}
			raw, err := json.Marshal(result.Items[0])
			if err != nil {
				t.Fatal(err)
			}
			var item map[string]any
			if err = json.Unmarshal(raw, &item); err != nil {
				t.Fatal(err)
			}
			if item["risk_confidence"] != tc.want {
				t.Fatalf("numeric risk confidence=%v want=%v", item["risk_confidence"], tc.want)
			}
		})
	}
}
