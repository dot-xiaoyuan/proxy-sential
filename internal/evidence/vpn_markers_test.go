package evidence

import (
	"bytes"
	"testing"
)

func TestVPNMarkersRequireWordBoundaries(t *testing.T) {
	for _, value := range []string{"store.apple.com", "history.example.test", "directory.example.test", "monitor.example.test", "storage.googleapis.com", "great.example.test", "greeting.example.test", "integrity.example.test", "ET INFO SSH greeting", "Attempted Administrator Privilege Gain", "Microsoft update", "algorithm.example.test", "sing-boxed.example.test"} {
		t.Run(value, func(t *testing.T) {
			if HasVPNHint(value) {
				t.Fatal("ordinary word fragment became a proxy marker")
			}
		})
	}
	for _, value := range []string{"student-vpn.example.test", "vpn2.example.test", "ET POLICY OpenVPN Client Connection", "WireGuard handshake", "Tor exit node", "torproject.org", "TorBrowser traffic", "GRE tunnel", "SOCKS5 greeting", "socks4 proxy", "v2rayN client", "v2rayng client", "sing-box client", "Xray-core", "shadowsocks.example.test", "IPSec tunnel", "HTTP CONNECT proxy hint"} {
		t.Run(value, func(t *testing.T) {
			if !HasVPNHint(value) {
				t.Fatal("explicit protocol/application marker was lost")
			}
		})
	}
}

func TestVPNRuleConfidenceReadsExactDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata any
		want     string
	}{
		{"list-high", []string{"proxy_sentinel_confidence high", "source proxy_sentinel"}, "high"},
		{"map-array", map[string]any{"proxy_sentinel_confidence": []any{"high"}}, "high"},
		{"map-string", map[string]any{"proxy_sentinel_confidence": "medium"}, "medium"},
		{"low", map[string]any{"proxy_sentinel_confidence": []any{"low"}}, "low"},
		{"hyphen", "proxy-sentinel-confidence=high", "high"},
		{"prefix", []string{"proxy_sentinel_confidence highly_unreliable"}, ""},
		{"irrelevant-value", map[string]any{"description": "proxy_sentinel_confidence high"}, ""},
		{"conflicting", []string{"proxy_sentinel_confidence high", "proxy_sentinel_confidence medium"}, "medium"},
		{"conflicting-low", map[string]any{"proxy_sentinel_confidence": []any{"high", "low"}}, "low"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ruleConfidence(tc.metadata); got != tc.want {
				t.Fatalf("metadata elevated confidence: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestVPNLowDeclarationDoesNotBecomeMediumEvidence(t *testing.T) {
	input := bytes.NewBufferString(normalizedLine("low-rule", "alert", map[string]any{"signature": "SOCKS5 hint", "metadata": map[string]any{"proxy_sentinel_confidence": []any{"low"}}}, nil) + "\n")
	result, err := Analyze(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Type != "vpn_proxy_rule_hint" || result.Evidence[0].Confidence > .4 || result.Evidence[0].Score > 20 || result.Evidence[0].Severity != "low" {
		t.Fatalf("low-confidence declaration was upgraded: %+v", result.Evidence)
	}
}
