package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed data/application_signatures.json
var embeddedApplicationSignatures []byte

const ApplicationSignatureVersion = "legacy-essentials-2026-09"

type ApplicationSignature struct {
	Pattern    string  `json:"pattern"`
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	Effect     string  `json:"effect"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
	License    string  `json:"license"`
	compiled   *regexp.Regexp
}
type ApplicationMatch struct {
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	Effect     string  `json:"effect"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"`
	License    string  `json:"license"`
	Version    string  `json:"version"`
}

var applicationState = struct {
	sync.RWMutex
	rules   []ApplicationSignature
	version string
}{rules: mustApplicationSignatures(embeddedApplicationSignatures), version: ApplicationSignatureVersion}

func ParseApplicationSignatures(data []byte) ([]ApplicationSignature, error) {
	var rules []ApplicationSignature
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	for index := range rules {
		rule := &rules[index]
		if strings.TrimSpace(rule.Pattern) == "" || rule.Name == "" || rule.Source == "" || rule.License == "" {
			return nil, fmt.Errorf("application signature %d lacks pattern, name, source or license", index)
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, err
		}
		rule.compiled = compiled
	}
	return rules, nil
}
func MatchApplication(values ...string) []ApplicationMatch {
	text := strings.Join(values, " ")
	applicationState.RLock()
	defer applicationState.RUnlock()
	result := []ApplicationMatch{}
	for _, rule := range applicationState.rules {
		if rule.compiled.MatchString(text) {
			result = append(result, ApplicationMatch{Name: rule.Name, Category: rule.Category, Effect: rule.Effect, Confidence: rule.Confidence, Source: rule.Source, License: rule.License, Version: applicationState.version})
		}
	}
	return result
}
func ApplicationRuleCount() int {
	applicationState.RLock()
	defer applicationState.RUnlock()
	return len(applicationState.rules)
}

func setApplicationSignatures(data []byte, version string) error {
	rules, err := ParseApplicationSignatures(data)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return fmt.Errorf("application signature library is empty")
	}
	applicationState.Lock()
	applicationState.rules, applicationState.version = rules, version
	applicationState.Unlock()
	return nil
}
func mustApplicationSignatures(data []byte) []ApplicationSignature {
	rules, err := ParseApplicationSignatures(data)
	if err != nil {
		panic(err)
	}
	return rules
}
