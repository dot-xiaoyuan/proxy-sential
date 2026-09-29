package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAnalyzeReplayAIRelayUsage runs the committed replay fixture and asserts
// that only hosts matching a known AI relay station produce the evidence.
func TestAnalyzeReplayAIRelayUsage(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "replay", "ai-relay-usage.jsonl")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer file.Close()

	result, err := Analyze(file, Options{Window: 10 * time.Minute})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	matched := map[string]Evidence{}
	for _, item := range result.Evidence {
		if item.Type != "ai_relay_domain_usage" {
			continue
		}
		matched[item.IP] = item
		if item.Score <= 0 || item.Confidence <= 0 || item.Window == "" || item.Reason == "" || item.CreatedAt == "" {
			t.Fatalf("ai relay evidence is missing required fields: %+v", item)
		}
		if item.Severity != "medium" && item.Severity != "high" {
			t.Fatalf("unexpected severity: %+v", item)
		}
		if len(item.Samples) == 0 {
			t.Fatalf("ai relay evidence has no samples: %+v", item)
		}
	}

	for _, ip := range []string{"10.20.0.11", "10.20.0.12", "10.20.0.16"} {
		if _, ok := matched[ip]; !ok {
			t.Fatalf("expected ai relay evidence for %s, got %+v", ip, matched)
		}
	}
	for _, ip := range []string{"10.20.0.13", "10.20.0.14", "10.20.0.15"} {
		if _, ok := matched[ip]; ok {
			t.Fatalf("official or lookalike host must not produce ai relay evidence for %s: %+v", ip, matched[ip])
		}
	}

	samples := matched["10.20.0.11"].Samples
	found := false
	for _, sample := range samples {
		if sample == "sni=api.yunwu.ai|云雾 API|relay|0.80|awesome-ai-api-proxy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unexpected samples for relay IP 10.20.0.11: %v", samples)
	}
}
