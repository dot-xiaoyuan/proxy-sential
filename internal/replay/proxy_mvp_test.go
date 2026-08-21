package replay

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

func TestProxyMVPReplayFixtures(t *testing.T) {
	tests := []struct {
		name            string
		fixture         string
		ip              string
		expectRuleMatch bool
		expectRiskLevel string
	}{
		{name: "explicit proxy rule becomes confirmed", fixture: "vpn-explicit-rule-match.jsonl", ip: "10.10.0.8", expectRuleMatch: true, expectRiskLevel: "confirmed"},
		{name: "video conference stays normal", fixture: "vpn-video-conference.jsonl", ip: "10.10.0.9", expectRiskLevel: "normal"},
		{name: "long encrypted connection stays normal", fixture: "vpn-low-confidence-long-connection.jsonl", ip: "10.10.0.10", expectRiskLevel: "normal"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "examples", "replay", test.fixture)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			replayResult, err := Analyze(bytes.NewReader(data), Options{Windows: []time.Duration{7 * 24 * time.Hour}})
			if err != nil {
				t.Fatal(err)
			}
			if replayResult.Stats.Accepted == 0 || replayResult.Stats.Malformed != 0 || replayResult.Stats.Skipped != 0 {
				t.Fatalf("fixture is not replayable: %+v", replayResult.Stats)
			}

			evidenceResult, err := evidence.Analyze(bytes.NewReader(data), evidence.Options{Window: 7 * 24 * time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			hasRuleMatch := false
			for _, item := range evidenceResult.Evidence {
				if item.Type == "vpn_proxy_rule_match" {
					hasRuleMatch = true
				}
				if !test.expectRuleMatch && item.Severity != "low" {
					t.Fatalf("benign/weak fixture emitted non-low proxy evidence: %+v", item)
				}
			}
			if hasRuleMatch != test.expectRuleMatch {
				t.Fatalf("unexpected rule-match evidence state: %+v", evidenceResult.Evidence)
			}

			evidenceJSON, err := json.Marshal(evidenceResult)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := risk.Inspect(bytes.NewReader(evidenceJSON), risk.InspectOptions{IP: test.ip})
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Level != test.expectRiskLevel {
				t.Fatalf("expected %s risk, got %+v", test.expectRiskLevel, snapshot)
			}
			if !test.expectRuleMatch && snapshot.RecommendedAction != "record" {
				t.Fatalf("weak behavior must not trigger policy action: %+v", snapshot)
			}
		})
	}
}
