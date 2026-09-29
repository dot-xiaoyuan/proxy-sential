package fingerprint

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const BrandEvidenceWindow = 7 * 24 * time.Hour

type BrandCandidate struct {
	Brand      string           `json:"brand"`
	Confidence float64          `json:"confidence"`
	Evidence   []DomainEvidence `json:"evidence"`
}

type BrandInference struct {
	Status      string           `json:"status"`
	Brand       string           `json:"brand,omitempty"`
	Confidence  float64          `json:"confidence"`
	Explanation string           `json:"explanation"`
	RuleVersion string           `json:"rule_version"`
	Window      string           `json:"window"`
	AsOf        string           `json:"as_of"`
	Candidates  []BrandCandidate `json:"candidates"`
}

// InferBrand consumes windowed, deduplicated observations. A service may be
// visible through several protocols or hostnames; it remains one service.
func InferBrand(items []DomainEvidence, version string, now time.Time, knownBrand string, knownConfidence float64) BrandInference {
	result := BrandInference{Status: "insufficient", RuleVersion: version, Window: "7d", AsOf: now.UTC().Format(time.RFC3339Nano), Candidates: []BrandCandidate{}, Explanation: "设备服务证据未达到品牌推测门槛"}
	groups := map[string][]DomainEvidence{}
	for _, item := range items {
		last, err := time.Parse(time.RFC3339Nano, item.LastSeen)
		if err != nil || last.Before(now.Add(-BrandEvidenceWindow)) || last.After(now) || item.RuleVersion != version || !item.Match.BrandEligible {
			continue
		}
		groups[item.Match.Ecosystem] = append(groups[item.Match.Ecosystem], item)
	}
	for brand, evidence := range groups {
		type service struct {
			count       int
			first, last time.Time
		}
		services := map[string]service{}
		score := 0.0
		for _, item := range evidence {
			key := item.Match.Service
			if key == "" {
				key = item.Match.RuleDomain
			}
			if key == "" {
				continue
			}
			first, e1 := time.Parse(time.RFC3339Nano, item.FirstSeen)
			last, e2 := time.Parse(time.RFC3339Nano, item.LastSeen)
			if e1 != nil || e2 != nil || first.Before(now.Add(-BrandEvidenceWindow)) || last.Before(first) {
				continue
			}
			v := services[key]
			v.count += item.Count
			if v.first.IsZero() || first.Before(v.first) {
				v.first = first
			}
			if last.After(v.last) {
				v.last = last
			}
			services[key] = v
			score = max(score, item.Match.Confidence)
		}
		qualifies := len(services) >= 2
		for _, v := range services {
			if v.count >= 3 && v.last.Sub(v.first) >= 10*time.Minute {
				qualifies = true
			}
		}
		if !qualifies {
			continue
		}
		sort.Slice(evidence, func(i, j int) bool {
			if evidence[i].Match.Domain != evidence[j].Match.Domain {
				return evidence[i].Match.Domain < evidence[j].Match.Domain
			}
			return evidence[i].EventSource < evidence[j].EventSource
		})
		if len(services) >= 2 {
			score += .05
		}
		result.Candidates = append(result.Candidates, BrandCandidate{Brand: brand, Confidence: min(score, .70), Evidence: evidence})
	}
	sort.Slice(result.Candidates, func(i, j int) bool { return result.Candidates[i].Brand < result.Candidates[j].Brand })
	if len(result.Candidates) == 1 {
		candidate := result.Candidates[0]
		result.Status = "inferred"
		result.Brand = candidate.Brand
		result.Confidence = candidate.Confidence
		result.Explanation = "厂商设备服务达到重复观察或多服务门槛；分值为规则评分，不是统计概率"
		if knownBrand != "" && knownBrand != "unknown" && knownConfidence >= .8 && !sameBrandEcosystem(knownBrand, candidate.Brand) {
			result.Status = "conflict"
			result.Brand = ""
			result.Explanation = "域名推测与已有高置信度品牌不一致，保留已有识别"
		}
	} else if len(result.Candidates) > 1 {
		result.Status = "conflict"
		result.Explanation = "多个品牌的设备服务均达到门槛，不能唯一推测品牌"
	}
	return result
}

func provenance(rule DomainSignature) []RuleProvenance {
	out := append([]RuleProvenance{}, rule.Sources...)
	return append(out, RuleProvenance{Name: rule.Source, URL: rule.SourceURL, Version: rule.SourceVersion})
}
func uniqueProvenance(values []RuleProvenance) []RuleProvenance {
	out := []RuleProvenance{}
	seen := map[RuleProvenance]bool{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Join([]string{out[i].Name, out[i].URL, out[i].Version}, "\x00") < strings.Join([]string{out[j].Name, out[j].URL, out[j].Version}, "\x00")
	})
	return out
}

type DomainSourceStatus struct {
	Name                   string `json:"name"`
	Version                string `json:"version"`
	RuleCount              int    `json:"rule_count"`
	BrandEligibleRuleCount int    `json:"brand_eligible_rule_count"`
}

func (l *Library) DomainSourceStatus() []DomainSourceStatus {
	values := map[string]DomainSourceStatus{}
	for _, rule := range l.domains {
		for _, source := range uniqueProvenance(provenance(rule)) {
			key := source.Name + ":" + source.Version
			v := values[key]
			v.Name = source.Name
			v.Version = source.Version
			v.RuleCount++
			if rule.BrandEligible {
				v.BrandEligibleRuleCount++
			}
			values[key] = v
		}
	}
	out := []DomainSourceStatus{}
	for _, v := range values {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].Version < out[j].Name+out[j].Version })
	return out
}

func (l *Library) DomainRulesJSON() []byte { data, _ := json.Marshal(l.domains); return data }

// LoadDomainLibrary restores an immutable domain-only snapshot for background
// reconciliation; it does not replace the independent device fingerprint library.
func LoadDomainLibrary(version string, data []byte) (*Library, error) {
	rules, index, err := parseDomainSignatures(data)
	if err != nil {
		return nil, err
	}
	return &Library{version: version, domains: rules, domainIndex: index}, nil
}
