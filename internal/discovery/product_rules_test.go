package discovery

import (
	"encoding/json"
	"testing"
)

func TestProductRuleTableCarriesProvenance(t *testing.T) {
	var table productRuleTable
	if err := json.Unmarshal(embeddedProductRules, &table); err != nil {
		t.Fatalf("decode product rule table: %v", err)
	}
	if table.Version == "" || table.Source == "" || table.SourceURL == "" || table.License == "" {
		t.Fatalf("product rule table must declare version, source, source_url and license: %+v", table)
	}
	if len(table.Entries) != 14 {
		t.Fatalf("product rule table entry count changed unexpectedly, got %d", len(table.Entries))
	}
}

func TestExactSADPModelRulesRejectNearMatches(t *testing.T) {
	for _, value := range []string{"DS-IPC-B12V2-I0", "DS-IPC-B12V2-I firmware", "DS-IPC-B12-I", "DS-IPC-T12-I", "DS-7808N-Q20", "DS-7808N-Q2/8P", "DS-7808N"} {
		if kind, _, model := ProductModelType(value); model != "" {
			t.Fatalf("%q must not match any product rule, got %s/%s", value, kind, model)
		}
	}
}

func TestParseProductRulesRejectInvalid(t *testing.T) {
	cases := map[string]string{
		"empty version":    `{"version":"","source":"x","entries":[{"pattern":"a","product_kind":"camera"}]}`,
		"empty source":     `{"version":"v1","source":"","entries":[{"pattern":"a","product_kind":"camera"}]}`,
		"no entries":       `{"version":"v1","source":"x","entries":[]}`,
		"bad regex":        `{"version":"v1","source":"x","entries":[{"pattern":"(","product_kind":"camera"}]}`,
		"missing kind":     `{"version":"v1","source":"x","entries":[{"pattern":"a","product_kind":""}]}`,
		"missing pattern":  `{"version":"v1","source":"x","entries":[{"pattern":"","product_kind":"camera"}]}`,
		"legacy bare list": `[{"pattern":"a","product_kind":"camera"}]`,
	}
	for name, data := range cases {
		if _, err := parseProductRules([]byte(data)); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}
