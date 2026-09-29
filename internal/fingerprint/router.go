package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed data/router_rules.json
var embeddedRouterRules []byte

type RouterThresholds struct {
	LikelyMin           int    `json:"likely_min"`
	ConfirmedMin        int    `json:"confirmed_min"`
	ConfirmedSourcesMin int    `json:"confirmed_sources_min"`
	EvidenceTTL         string `json:"evidence_ttl"`
	AssociationWindow   string `json:"association_window"`
}

type RouterRule struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Inputs       []string `json:"inputs"`
	Match        string   `json:"match"`
	Pattern      string   `json:"pattern"`
	Brand        string   `json:"brand,omitempty"`
	Series       string   `json:"series,omitempty"`
	Model        string   `json:"model,omitempty"`
	Role         string   `json:"role"`
	Strength     string   `json:"strength"`
	Score        int      `json:"score"`
	Exclude      bool     `json:"exclude"`
	ConflictCode string   `json:"conflict_code,omitempty"`
	Explanation  string   `json:"explanation"`
	compiled     *regexp.Regexp
}

type RouterRuleSet struct {
	Version    string           `json:"version"`
	Thresholds RouterThresholds `json:"thresholds"`
	Rules      []RouterRule     `json:"rules"`
}

type RouterRuleMatch struct {
	Rule      RouterRule `json:"rule"`
	Input     string     `json:"input"`
	RawValue  string     `json:"raw_value"`
	Brand     string     `json:"brand,omitempty"`
	Series    string     `json:"series,omitempty"`
	Model     string     `json:"model,omitempty"`
	BrandOnly bool       `json:"brand_reference_only"`
}

var (
	routerRulesMu sync.RWMutex
	routerRules   = mustLoadRouterRuleSet(embeddedRouterRules)
)

func EmbeddedRouterRules() []byte { return append([]byte(nil), embeddedRouterRules...) }

func DefaultRouterRuleSet() *RouterRuleSet {
	routerRulesMu.RLock()
	defer routerRulesMu.RUnlock()
	return routerRules
}

func SetDefaultRouterRuleSet(rules *RouterRuleSet) {
	if rules == nil {
		return
	}
	routerRulesMu.Lock()
	routerRules = rules
	routerRulesMu.Unlock()
}

func LoadRouterRuleSet(data []byte) (*RouterRuleSet, error) {
	if len(data) == 0 {
		data = embeddedRouterRules
	}
	var result RouterRuleSet
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode router rules: %w", err)
	}
	if strings.TrimSpace(result.Version) == "" || len(result.Rules) == 0 {
		return nil, fmt.Errorf("router rules require a version and at least one rule")
	}
	if result.Thresholds.LikelyMin <= 0 || result.Thresholds.ConfirmedMin <= result.Thresholds.LikelyMin || result.Thresholds.ConfirmedSourcesMin < 2 {
		return nil, fmt.Errorf("invalid router thresholds")
	}
	if _, err := time.ParseDuration(result.Thresholds.EvidenceTTL); err != nil {
		return nil, fmt.Errorf("invalid router evidence_ttl: %w", err)
	}
	if _, err := time.ParseDuration(result.Thresholds.AssociationWindow); err != nil {
		return nil, fmt.Errorf("invalid router association_window: %w", err)
	}
	seen := map[string]bool{}
	for index := range result.Rules {
		rule := &result.Rules[index]
		if rule.ID == "" || rule.Version == "" || len(rule.Inputs) == 0 || rule.Pattern == "" || rule.Explanation == "" || seen[rule.ID] {
			return nil, fmt.Errorf("invalid or duplicate router rule at index %d", index)
		}
		seen[rule.ID] = true
		if rule.Match != "regex" {
			return nil, fmt.Errorf("router rule %s has unsupported match type", rule.ID)
		}
		compiled, err := regexp.Compile("(?i)" + rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile router rule %s: %w", rule.ID, err)
		}
		rule.compiled = compiled
	}
	return &result, nil
}

func (r *RouterRuleSet) Match(inputs map[string][]string) []RouterRuleMatch {
	if r == nil {
		return nil
	}
	matches := []RouterRuleMatch{}
	for _, rule := range r.Rules {
		matched := false
		for _, input := range rule.Inputs {
			for _, raw := range inputs[input] {
				indexes := rule.compiled.FindStringSubmatchIndex(raw)
				if indexes == nil {
					continue
				}
				expand := func(value string) string {
					if value == "" {
						return ""
					}
					return strings.TrimSpace(string(rule.compiled.ExpandString(nil, value, raw, indexes)))
				}
				matches = append(matches, RouterRuleMatch{Rule: rule, Input: input, RawValue: raw, Brand: expand(rule.Brand), Series: expand(rule.Series), Model: expand(rule.Model), BrandOnly: rule.Role == "unknown"})
				matched = true
				break
			}
			if matched {
				break
			}
		}
	}
	return matches
}

func mustLoadRouterRuleSet(data []byte) *RouterRuleSet {
	rules, err := LoadRouterRuleSet(data)
	if err != nil {
		panic(err)
	}
	return rules
}
