package fingerprint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

const (
	DomainMatchExact     = "exact"
	DomainMatchSubdomain = "subdomain"
)

var validDomainCategories = map[string]bool{"telemetry": true, "update": true, "push": true, "device_cloud": true}

type DomainSignature struct {
	Domain     string  `json:"domain"`
	MatchType  string  `json:"match_type"`
	Ecosystem  string  `json:"ecosystem"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
}

type DomainMatch struct {
	Domain     string  `json:"domain"`
	RuleDomain string  `json:"rule_domain"`
	MatchType  string  `json:"match_type"`
	Ecosystem  string  `json:"ecosystem"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
}

type domainNode struct {
	children map[string]*domainNode
	exact    *DomainSignature
	suffix   *DomainSignature
}

func parseDomainSignatures(data []byte) ([]DomainSignature, *domainNode, error) {
	if len(data) == 0 {
		data = []byte("[]")
	}
	var rules []DomainSignature
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, nil, fmt.Errorf("decode domain signatures: %w", err)
	}
	root := &domainNode{children: map[string]*domainNode{}}
	seen := map[string]string{}
	for index := range rules {
		rule := &rules[index]
		rule.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rule.Domain)), ".")
		ascii, err := idna.Lookup.ToASCII(rule.Domain)
		if err != nil || ascii == "" || strings.ContainsAny(ascii, "/\\?#@:") {
			return nil, nil, fmt.Errorf("domain signature %d has invalid domain", index)
		}
		rule.Domain = ascii
		rule.MatchType = strings.ToLower(strings.TrimSpace(rule.MatchType))
		if rule.MatchType != DomainMatchExact && rule.MatchType != DomainMatchSubdomain {
			return nil, nil, fmt.Errorf("domain signature %d has invalid match_type", index)
		}
		rule.Ecosystem = strings.TrimSpace(rule.Ecosystem)
		rule.Category = strings.ToLower(strings.TrimSpace(rule.Category))
		rule.Source = strings.TrimSpace(rule.Source)
		if rule.Ecosystem == "" || rule.Source == "" || !validDomainCategories[rule.Category] || rule.Confidence <= 0 || rule.Confidence > 0.70 {
			return nil, nil, fmt.Errorf("domain signature %d has invalid ecosystem metadata", index)
		}
		if strings.EqualFold(rule.Source, "nextdns") && rule.Confidence > 0.55 {
			return nil, nil, fmt.Errorf("NextDNS domain signature %d exceeds confidence cap", index)
		}
		key := rule.MatchType + ":" + rule.Domain
		if ecosystem, ok := seen[key]; ok {
			if !strings.EqualFold(ecosystem, rule.Ecosystem) {
				return nil, nil, fmt.Errorf("domain %q maps to conflicting ecosystems", rule.Domain)
			}
			return nil, nil, fmt.Errorf("duplicate domain signature %q", rule.Domain)
		}
		seen[key] = rule.Ecosystem
		node := root
		labels := strings.Split(rule.Domain, ".")
		for labelIndex := len(labels) - 1; labelIndex >= 0; labelIndex-- {
			if node.children[labels[labelIndex]] == nil {
				node.children[labels[labelIndex]] = &domainNode{children: map[string]*domainNode{}}
			}
			node = node.children[labels[labelIndex]]
		}
		copyRule := *rule
		if rule.MatchType == DomainMatchExact {
			node.exact = &copyRule
		} else {
			node.suffix = &copyRule
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Domain != rules[j].Domain {
			return rules[i].Domain < rules[j].Domain
		}
		return rules[i].MatchType < rules[j].MatchType
	})
	return rules, root, nil
}

func encodeDomainSignatures(rules []DomainSignature) ([]byte, error) {
	data, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}
	rules, _, err = parseDomainSignatures(data)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(rules, "", "  ")
}
