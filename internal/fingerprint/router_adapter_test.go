package fingerprint

import "testing"

func TestRouterRulesRejectTPLinkAdapters(t *testing.T) {
	rules, err := LoadRouterRuleSet(EmbeddedRouterRules())
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"TP-Link", "TP-Link TL-WN823N", "TP-Link Archer T3U", "TP-Link Archer TX20U", "TP-Link Archer TBE400E", "TP-Link UE300", "TP-Link TG-3468"} {
		for _, match := range rules.Match(map[string][]string{"hostname": {input}, "http_title": {input}}) {
			if match.Rule.Role == "router" && !match.Rule.Exclude {
				t.Errorf("adapter %q matched router rule %s", input, match.Rule.ID)
			}
		}
	}
	for _, input := range []string{"TP-Link Archer C7", "TP-Link Archer AX55", "TP-Link Archer BE800", "TP-Link Omada ER605", "TL-WDR5620"} {
		found := false
		for _, match := range rules.Match(map[string][]string{"hostname": {input}}) {
			found = found || match.Rule.Role == "router" && !match.Rule.Exclude
		}
		if !found {
			t.Errorf("router %q no longer matches", input)
		}
	}
}
