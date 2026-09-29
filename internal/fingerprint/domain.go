package fingerprint

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	DomainMatchExact     = "exact"
	DomainMatchSubdomain = "subdomain"
)

var validDomainCategories = map[string]bool{"telemetry": true, "update": true, "push": true, "device_cloud": true, "activation": true, "device_management": true}

type RuleProvenance struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Version string `json:"version"`
}

type DomainSignature struct {
	SourceURL     string           `json:"source_url,omitempty"`
	SourceVersion string           `json:"source_version,omitempty"`
	Sources       []RuleProvenance `json:"sources,omitempty"`
	Service       string           `json:"service,omitempty"`
	Purpose       string           `json:"purpose,omitempty"`
	OSFamilies    []string         `json:"os_families,omitempty"`
	BrandEligible bool             `json:"brand_eligible,omitempty"`

	Domain     string  `json:"domain"`
	MatchType  string  `json:"match_type"`
	Ecosystem  string  `json:"ecosystem"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
}

type DomainMatch struct {
	SourceURL     string           `json:"source_url,omitempty"`
	SourceVersion string           `json:"source_version,omitempty"`
	Sources       []RuleProvenance `json:"sources,omitempty"`
	Service       string           `json:"service,omitempty"`
	Purpose       string           `json:"purpose,omitempty"`
	OSFamilies    []string         `json:"os_families,omitempty"`
	BrandEligible bool             `json:"brand_eligible,omitempty"`

	Domain     string  `json:"domain"`
	RuleDomain string  `json:"rule_domain"`
	MatchType  string  `json:"match_type"`
	Ecosystem  string  `json:"ecosystem"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
}

type DomainEvidence struct {
	AttributionMethod string      `json:"attribution_method,omitempty"`
	RuleVersion       string      `json:"rule_version,omitempty"`
	EventIDs          []string    `json:"event_ids,omitempty"`
	EventSource       string      `json:"event_source,omitempty"`
	Match             DomainMatch `json:"match"`
	FirstSeen         string      `json:"first_seen"`
	LastSeen          string      `json:"last_seen"`
	Count             int         `json:"count"`
}

type EcosystemResult struct {
	Hint            string  `json:"ecosystem_hint,omitempty"`
	Confidence      float64 `json:"ecosystem_confidence"`
	Conflict        bool    `json:"ecosystem_conflict"`
	EvidenceCount   int     `json:"ecosystem_evidence_count"`
	DistinctDomains int     `json:"distinct_domains"`
	Displayable     bool    `json:"displayable"`
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
		if rule.BrandEligible && (rule.Service == "" || rule.Purpose == "" || rule.SourceURL == "" || rule.SourceVersion == "") {
			return nil, nil, fmt.Errorf("brand eligible rule requires service, purpose and provenance")
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
	unique := make([]DomainSignature, 0, len(rules))
	seen := map[string]string{}
	indexes := map[string]int{}
	for _, rule := range rules {
		key := strings.ToLower(strings.TrimSpace(rule.MatchType)) + ":" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Domain), "."))
		if ecosystem, ok := seen[key]; ok {
			if !strings.EqualFold(ecosystem, rule.Ecosystem) {
				return nil, fmt.Errorf("domain %q maps to conflicting ecosystems", rule.Domain)
			}
			i := indexes[key]
			merged := append(unique[i].Sources, provenance(rule)...)
			if rule.BrandEligible && !unique[i].BrandEligible {
				unique[i] = rule
			}
			unique[i].Sources = uniqueProvenance(merged)
			continue
		}
		seen[key] = rule.Ecosystem
		indexes[key] = len(unique)
		rule.Sources = uniqueProvenance(provenance(rule))
		unique = append(unique, rule)
	}
	data, err := json.Marshal(unique)
	if err != nil {
		return nil, err
	}
	rules, _, err = parseDomainSignatures(data)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(rules, "", "  ")
}

func (l *Library) DomainRuleCount() int { return len(l.domains) }

func (l *Library) DomainEcosystemCount() int {
	values := map[string]struct{}{}
	for _, rule := range l.domains {
		values[strings.ToLower(rule.Ecosystem)] = struct{}{}
	}
	return len(values)
}

// MatchDomain uses a reversed-label trie. A suffix rule is considered only at
// a complete label boundary, so fakeapple.com cannot match apple.com.
func (l *Library) MatchDomain(value string) (DomainMatch, bool) {
	domain, err := normalizeDomain(value)
	if err != nil || domain == "" || l.domainIndex == nil {
		return DomainMatch{}, false
	}
	labels := strings.Split(domain, ".")
	node := l.domainIndex
	var candidate *DomainSignature
	for index := len(labels) - 1; index >= 0; index-- {
		node = node.children[labels[index]]
		if node == nil {
			break
		}
		if node.suffix != nil {
			candidate = node.suffix
		}
		if index == 0 && node.exact != nil {
			candidate = node.exact
		}
	}
	if candidate == nil {
		return DomainMatch{}, false
	}
	return DomainMatch{SourceURL: candidate.SourceURL, SourceVersion: candidate.SourceVersion, Sources: candidate.Sources, Service: candidate.Service, Purpose: candidate.Purpose, OSFamilies: candidate.OSFamilies, BrandEligible: candidate.BrandEligible, Domain: domain, RuleDomain: candidate.Domain, MatchType: candidate.MatchType, Ecosystem: candidate.Ecosystem, Category: candidate.Category, Confidence: candidate.Confidence, Source: candidate.Source}, true
}

func EvaluateEcosystem(evidence []DomainEvidence) EcosystemResult {
	type aggregate struct {
		name        string
		confidence  float64
		count       int
		domains     map[string]struct{}
		displayable bool
	}
	byEcosystem := map[string]*aggregate{}
	for _, item := range evidence {
		name := strings.TrimSpace(item.Match.Ecosystem)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		current := byEcosystem[key]
		if current == nil {
			current = &aggregate{name: name, domains: map[string]struct{}{}}
			byEcosystem[key] = current
		}
		current.count += max(item.Count, 1)
		serviceKey := item.Match.Service
		if serviceKey == "" {
			serviceKey = item.Match.RuleDomain
		}
		if serviceKey == "" {
			serviceKey = item.Match.Domain
		}
		current.domains[serviceKey] = struct{}{}
		if item.Match.Confidence > current.confidence {
			current.confidence = item.Match.Confidence
		}
		first, firstErr := time.Parse(time.RFC3339Nano, item.FirstSeen)
		last, lastErr := time.Parse(time.RFC3339Nano, item.LastSeen)
		if item.Count >= 3 && firstErr == nil && lastErr == nil && last.Sub(first) >= 10*time.Minute {
			current.displayable = true
		}
	}
	type ranked struct {
		name string
		*aggregate
	}
	ranking := []ranked{}
	for _, current := range byEcosystem {
		if len(current.domains) >= 2 {
			current.confidence = min(current.confidence+0.05, 0.70)
			current.displayable = true
		}
		found := false
		for _, existing := range ranking {
			if strings.EqualFold(existing.name, current.name) {
				found = true
				break
			}
		}
		if !found {
			ranking = append(ranking, ranked{current.name, current})
		}
	}
	sort.Slice(ranking, func(i, j int) bool {
		if ranking[i].confidence != ranking[j].confidence {
			return ranking[i].confidence > ranking[j].confidence
		}
		return ranking[i].name < ranking[j].name
	})
	if len(ranking) == 0 {
		return EcosystemResult{}
	}
	result := EcosystemResult{Hint: ranking[0].name, Confidence: ranking[0].confidence, EvidenceCount: ranking[0].count, DistinctDomains: len(ranking[0].domains), Displayable: ranking[0].displayable}
	if len(ranking) > 1 && ranking[0].confidence >= 0.55 && ranking[1].confidence >= 0.55 {
		result.Conflict = true
		result.Displayable = false
	}
	return result
}

// FuseEcosystemBrand only raises confidence for an already independent and
// agreeing brand signal. OUI plus ecosystem is explicitly not a brand proof.
func FuseEcosystemBrand(brand string, brandConfidence float64, source string, ecosystem EcosystemResult) (string, float64, bool) {
	brand = strings.TrimSpace(brand)
	if !ecosystem.Displayable || brand == "" || ecosystem.Hint == "" || ecosystem.Conflict || strings.EqualFold(source, "ieee_oui") || !sameBrandEcosystem(brand, ecosystem.Hint) {
		return brand, brandConfidence, false
	}
	combined := 1 - (1-brandConfidence)*(1-ecosystem.Confidence)
	if combined < 0.8 {
		return brand, brandConfidence, false
	}
	return brand, min(combined, 1), true
}

func sameBrandEcosystem(brand, ecosystem string) bool {
	normalize := func(value string) string {
		value = strings.ToLower(value)
		for _, prefix := range []string{"amazon ", "microsoft "} {
			value = strings.TrimPrefix(value, prefix)
		}
		return strings.NewReplacer(" ", "", "-", "", "_", "").Replace(value)
	}
	return normalize(brand) == normalize(ecosystem)
}

func normalizeDomain(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "/\\?#@") {
		return "", fmt.Errorf("invalid domain")
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.Count(value, ":") == 1 {
		if index := strings.LastIndexByte(value, ':'); index > 0 {
			if port, portErr := strconv.Atoi(value[index+1:]); portErr == nil && port > 0 && port <= 65535 {
				value = value[:index]
			}
		}
	}
	value = strings.TrimSuffix(strings.Trim(value, "[]"), ".")
	if net.ParseIP(value) != nil {
		return "", fmt.Errorf("invalid domain")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", err
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid domain")
		}
	}
	return ascii, nil
}
