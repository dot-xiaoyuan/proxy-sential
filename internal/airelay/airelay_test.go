package airelay

import "testing"

func TestEmbeddedAssetLoads(t *testing.T) {
	matcher := Default()
	if matcher.IndicatorCount() == 0 {
		t.Fatal("embedded indicator asset is empty")
	}
	if matcher.Version() == "" {
		t.Fatal("embedded indicator asset has no version")
	}
}

func TestMatchSubdomainOnLabelBoundary(t *testing.T) {
	matcher := Default()
	cases := []struct {
		host  string
		want  string
		found bool
	}{
		{"api.yunwu.ai", "yunwu.ai", true},
		{"YUNWU.AI.", "yunwu.ai", true},
		{"chat.yunwu.ai:443", "yunwu.ai", true},
		{"notyunwu.ai", "", false},
		{"yunwu.ai.evil.example", "", false},
		{"api.openai.com", "", false},
		{"api.anthropic.com", "", false},
		{"", "", false},
		{"not a host", "", false},
	}
	for _, tc := range cases {
		got, ok := matcher.Match(tc.host)
		if ok != tc.found {
			t.Fatalf("Match(%q) found=%v want %v", tc.host, ok, tc.found)
		}
		if ok && got.Domain != tc.want {
			t.Fatalf("Match(%q) domain=%q want %q", tc.host, got.Domain, tc.want)
		}
	}
}

func TestOfficialDomainIsNeverARelay(t *testing.T) {
	matcher := Default()
	for _, host := range []string{"api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com"} {
		if !matcher.IsOfficial(host) {
			t.Fatalf("%q should be declared official", host)
		}
		if _, ok := matcher.Match(host); ok {
			t.Fatalf("official host %q must not match a relay indicator", host)
		}
	}
}

func TestLoadRejectsInvalidAssets(t *testing.T) {
	base := `{"schema_version":"ai-relay-indicators/v1","version":"t","sources":[{"id":"s","name":"n","url":"u"}],`
	cases := map[string]string{
		"bad schema":     `{"schema_version":"x","version":"t","sources":[{"id":"s","name":"n","url":"u"}],"indicators":[]}`,
		"no sources":     `{"schema_version":"ai-relay-indicators/v1","version":"t","sources":[],"indicators":[]}`,
		"unknown source": base + `"indicators":[{"domain":"a.example","match_type":"subdomain","category":"relay","confidence":0.7,"status":"resolved","source":"missing"}]}`,
		"bad match":      base + `"indicators":[{"domain":"a.example","match_type":"glob","category":"relay","confidence":0.7,"status":"resolved","source":"s"}]}`,
		"bad category":   base + `"indicators":[{"domain":"a.example","match_type":"exact","category":"vpn","confidence":0.7,"status":"resolved","source":"s"}]}`,
		"bad status":     base + `"indicators":[{"domain":"a.example","match_type":"exact","category":"relay","confidence":0.7,"status":"maybe","source":"s"}]}`,
		"bad conf":       base + `"indicators":[{"domain":"a.example","match_type":"exact","category":"relay","confidence":0.99,"status":"resolved","source":"s"}]}`,
		"bad host":       base + `"indicators":[{"domain":"bad host","match_type":"exact","category":"relay","confidence":0.7,"status":"resolved","source":"s"}]}`,
		"official clash": base + `"official_domains":["a.example"],"indicators":[{"domain":"a.example","match_type":"exact","category":"relay","confidence":0.7,"status":"resolved","source":"s"}]}`,
		"duplicate":      base + `"indicators":[{"domain":"a.example","match_type":"exact","category":"relay","confidence":0.7,"status":"resolved","source":"s"},{"domain":"a.example","match_type":"exact","category":"relay","confidence":0.7,"status":"resolved","source":"s"}]}`,
		"unknown field":  base + `"extra":1,"indicators":[]}`,
	}
	for name, body := range cases {
		if _, err := Load([]byte(body)); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

func TestLoadAcceptsMinimalAsset(t *testing.T) {
	body := `{"schema_version":"ai-relay-indicators/v1","version":"t","updated_at":"2026-01-01",` +
		`"sources":[{"id":"s","name":"n","url":"u"}],` +
		`"official_domains":["official.example"],` +
		`"indicators":[{"domain":"relay.example","match_type":"subdomain","category":"relay","confidence":0.7,"status":"resolved","source":"s"}]}`
	matcher, err := Load([]byte(body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := matcher.Match("api.relay.example"); !ok {
		t.Fatal("subdomain should match")
	}
	if _, ok := matcher.Match("x.relay.example.evil"); ok {
		t.Fatal("suffix must respect label boundary")
	}
	if _, ok := matcher.Match("official.example"); ok {
		t.Fatal("official domain must be excluded")
	}
}
