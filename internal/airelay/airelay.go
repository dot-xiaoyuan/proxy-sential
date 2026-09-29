// Package airelay matches observable host names (DNS query, TLS SNI, HTTP Host)
// against a curated, versioned list of AI API relay stations ("AI 中转站").
//
// The package only answers "does this observable host belong to a known relay
// endpoint". It does not read raw capture fields, does not score risk and does
// not decide policy. Callers turn a match into a standard evidence item so the
// risk engine keeps working on the standard event model.
package airelay

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed data/indicators.json
var embeddedIndicators []byte

const SchemaVersion = "ai-relay-indicators/v1"

const (
	MatchExact     = "exact"
	MatchSubdomain = "subdomain"

	CategoryRelay      = "relay"
	CategoryAggregator = "aggregator"

	StatusResolved   = "resolved"
	StatusUnresolved = "unresolved"
)

var (
	validMatchTypes = map[string]bool{MatchExact: true, MatchSubdomain: true}
	validCategories = map[string]bool{CategoryRelay: true, CategoryAggregator: true}
	validStatuses   = map[string]bool{StatusResolved: true, StatusUnresolved: true}
	hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)
)

// Source records where an indicator came from so a reviewer can judge it.
type Source struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Version string `json:"version,omitempty"`
}

// Indicator is one relay endpoint rule.
type Indicator struct {
	Domain     string  `json:"domain"`
	MatchType  string  `json:"match_type"`
	Category   string  `json:"category"`
	Name       string  `json:"name,omitempty"`
	Confidence float64 `json:"confidence"`
	Status     string  `json:"status"`
	Source     string  `json:"source"`
	Note       string  `json:"note,omitempty"`
}

type asset struct {
	SchemaVersion   string      `json:"schema_version"`
	Version         string      `json:"version"`
	UpdatedAt       string      `json:"updated_at"`
	Sources         []Source    `json:"sources"`
	OfficialDomains []string    `json:"official_domains"`
	Indicators      []Indicator `json:"indicators"`
}

type node struct {
	children map[string]*node
	exact    *Indicator
	suffix   *Indicator
}

// Matcher is an immutable, concurrency-safe indicator set.
type Matcher struct {
	version    string
	updatedAt  string
	indicators []Indicator
	official   map[string]struct{}
	root       *node
}

var (
	defaultOnce    sync.Once
	defaultMatcher *Matcher
)

// Default returns the embedded indicator set. The embedded asset is validated
// at package init, so a malformed asset fails the build rather than a request.
func Default() *Matcher {
	defaultOnce.Do(func() {
		matcher, err := Load(embeddedIndicators)
		if err != nil {
			panic(fmt.Errorf("load embedded ai relay indicators: %w", err))
		}
		defaultMatcher = matcher
	})
	return defaultMatcher
}

func (m *Matcher) Version() string   { return m.version }
func (m *Matcher) UpdatedAt() string { return m.updatedAt }
func (m *Matcher) IndicatorCount() int {
	if m == nil {
		return 0
	}
	return len(m.indicators)
}

// Load parses and validates an indicator asset. Invalid data is rejected
// instead of being partially applied.
func Load(data []byte) (*Matcher, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty ai relay indicator asset")
	}
	var doc asset
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode ai relay indicators: %w", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported ai relay schema version %q", doc.SchemaVersion)
	}
	if strings.TrimSpace(doc.Version) == "" {
		return nil, fmt.Errorf("ai relay indicator asset is missing version")
	}
	sources := map[string]Source{}
	for index, source := range doc.Sources {
		id := strings.TrimSpace(source.ID)
		if id == "" || strings.TrimSpace(source.Name) == "" || strings.TrimSpace(source.URL) == "" {
			return nil, fmt.Errorf("ai relay source %d is missing id, name or url", index)
		}
		if _, ok := sources[id]; ok {
			return nil, fmt.Errorf("duplicate ai relay source id %q", id)
		}
		source.ID = id
		sources[id] = source
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("ai relay indicator asset declares no sources")
	}

	matcher := &Matcher{
		version:   doc.Version,
		updatedAt: doc.UpdatedAt,
		official:  map[string]struct{}{},
		root:      &node{children: map[string]*node{}},
	}
	for index, domain := range doc.OfficialDomains {
		normalized, err := normalizeHost(domain)
		if err != nil {
			return nil, fmt.Errorf("official domain %d: %w", index, err)
		}
		matcher.official[normalized] = struct{}{}
	}

	seen := map[string]struct{}{}
	for index := range doc.Indicators {
		rule := doc.Indicators[index]
		normalized, err := normalizeHost(rule.Domain)
		if err != nil {
			return nil, fmt.Errorf("indicator %d: %w", index, err)
		}
		rule.Domain = normalized
		rule.MatchType = strings.ToLower(strings.TrimSpace(rule.MatchType))
		rule.Category = strings.ToLower(strings.TrimSpace(rule.Category))
		rule.Status = strings.ToLower(strings.TrimSpace(rule.Status))
		rule.Source = strings.TrimSpace(rule.Source)
		if !validMatchTypes[rule.MatchType] {
			return nil, fmt.Errorf("indicator %q has invalid match_type %q", rule.Domain, rule.MatchType)
		}
		if !validCategories[rule.Category] {
			return nil, fmt.Errorf("indicator %q has invalid category %q", rule.Domain, rule.Category)
		}
		if !validStatuses[rule.Status] {
			return nil, fmt.Errorf("indicator %q has invalid status %q", rule.Domain, rule.Status)
		}
		if rule.Confidence <= 0 || rule.Confidence > 0.90 {
			return nil, fmt.Errorf("indicator %q confidence must be within (0, 0.90]", rule.Domain)
		}
		if _, ok := sources[rule.Source]; !ok {
			return nil, fmt.Errorf("indicator %q references unknown source %q", rule.Domain, rule.Source)
		}
		if _, ok := matcher.official[rule.Domain]; ok {
			return nil, fmt.Errorf("indicator %q is also declared as an official provider domain", rule.Domain)
		}
		key := rule.MatchType + ":" + rule.Domain
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate ai relay indicator %q", rule.Domain)
		}
		seen[key] = struct{}{}
		insert(matcher.root, rule)
		matcher.indicators = append(matcher.indicators, rule)
	}
	sort.Slice(matcher.indicators, func(i, j int) bool {
		if matcher.indicators[i].Domain != matcher.indicators[j].Domain {
			return matcher.indicators[i].Domain < matcher.indicators[j].Domain
		}
		return matcher.indicators[i].MatchType < matcher.indicators[j].MatchType
	})
	return matcher, nil
}

func insert(root *node, rule Indicator) {
	current := root
	labels := strings.Split(rule.Domain, ".")
	for index := len(labels) - 1; index >= 0; index-- {
		if current.children[labels[index]] == nil {
			current.children[labels[index]] = &node{children: map[string]*node{}}
		}
		current = current.children[labels[index]]
	}
	copied := rule
	if rule.MatchType == MatchExact {
		current.exact = &copied
	} else {
		current.suffix = &copied
	}
}

// IsOfficial reports whether a host belongs to a first-party AI provider that
// was explicitly declared in the asset. It exists so relay indicators can never
// shadow an official endpoint.
func (m *Matcher) IsOfficial(host string) bool {
	if m == nil {
		return false
	}
	normalized, err := normalizeHost(host)
	if err != nil {
		return false
	}
	_, ok := m.official[normalized]
	return ok
}

// Match resolves the longest relay indicator covering host. A suffix rule only
// matches on a complete label boundary, so "notyunwu.ai" never matches
// "yunwu.ai", while "api.yunwu.ai" does.
func (m *Matcher) Match(host string) (Indicator, bool) {
	if m == nil || m.root == nil {
		return Indicator{}, false
	}
	normalized, err := normalizeHost(host)
	if err != nil {
		return Indicator{}, false
	}
	if _, ok := m.official[normalized]; ok {
		return Indicator{}, false
	}
	labels := strings.Split(normalized, ".")
	current := m.root
	var candidate *Indicator
	for index := len(labels) - 1; index >= 0; index-- {
		current = current.children[labels[index]]
		if current == nil {
			break
		}
		if current.suffix != nil {
			candidate = current.suffix
		}
		if index == 0 && current.exact != nil {
			candidate = current.exact
		}
	}
	if candidate == nil {
		return Indicator{}, false
	}
	return *candidate, true
}

func normalizeHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	host = strings.TrimPrefix(host, "*.")
	if index := strings.Index(host, "://"); index >= 0 {
		host = host[index+3:]
	}
	if index := strings.IndexAny(host, "/?#"); index >= 0 {
		host = host[:index]
	}
	if index := strings.LastIndex(host, ":"); index >= 0 && !strings.Contains(host, "]") {
		host = host[:index]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if len(host) > 253 || !hostnamePattern.MatchString(host) {
		return "", fmt.Errorf("invalid host %q", value)
	}
	return host, nil
}
