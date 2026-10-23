package airelay

import (
	"os"
	"strings"
	"testing"
)

func TestMaterializedMatchViewCoversIndicatorAsset(t *testing.T) {
	sql, err := os.ReadFile("../../migrations/clickhouse/048_ai_relay_domain_matches_update.sql")
	if err != nil {
		t.Fatal(err)
	}
	view := string(sql)
	matcher := Default()
	if !strings.Contains(view, "AS indicator_version") || !strings.Contains(view, "'"+matcher.Version()+"'") {
		t.Fatal("materialized view indicator version differs from embedded asset")
	}
	for _, indicator := range matcher.Indicators() {
		if !strings.Contains(view, "domain='"+indicator.Domain+"'") {
			t.Errorf("materialized view missing indicator %s", indicator.Domain)
		}
	}
	for _, domain := range matcher.OfficialDomains() {
		if !strings.Contains(view, "'"+domain+"'") {
			t.Errorf("materialized view missing official exclusion %s", domain)
		}
	}
}

func TestEmbeddedAssetLoads(t *testing.T) {
	matcher := Default()
	if matcher.IndicatorCount() == 0 {
		t.Fatal("embedded indicator asset is empty")
	}
	if matcher.Version() == "" {
		t.Fatal("embedded indicator asset has no version")
	}
}

func TestCCTQAndMICUIndicators(t *testing.T) {
	matcher := Default()
	for _, tc := range []struct{ host, domain, nameZH string }{
		{"www.cctq.ai", "cctq.ai", "CCTQ 中转站"},
		{"cf-fast.cctq.ai", "cctq.ai", "CCTQ 中转站"},
		{"www.micuapi.ai", "micuapi.ai", "米醋中转站"},
	} {
		indicator, ok := matcher.Match(tc.host)
		if !ok || indicator.Domain != tc.domain || indicator.NameZH != tc.nameZH {
			t.Errorf("Match(%q) = %+v, %v", tc.host, indicator, ok)
		}
	}
	for _, host := range []string{"fakecctq.ai", "cctq.ai.evil.example", "notmicuapi.ai", "micuapi.ai.evil.example", "micu.cc"} {
		if _, ok := matcher.Match(host); ok {
			t.Errorf("unexpected relay match for %q", host)
		}
	}
	for _, indicator := range matcher.Indicators() {
		if indicator.NameZH == "" {
			t.Errorf("missing Chinese display name for %q", indicator.Domain)
		}
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
