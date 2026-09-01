package fingerprint

import (
	"encoding/json"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

type uapDocument struct {
	DeviceParsers []struct {
		Regex             string `yaml:"regex"`
		RegexFlag         string `yaml:"regex_flag"`
		DeviceReplacement string `yaml:"device_replacement"`
		BrandReplacement  string `yaml:"brand_replacement"`
		ModelReplacement  string `yaml:"model_replacement"`
	} `yaml:"device_parsers"`
}

// RulesFromUAP converts only device parsers that Go can compile. Unsupported
// PCRE constructs are skipped instead of making an upstream refresh unsafe.
func RulesFromUAP(data []byte) ([]Rule, error) {
	var document uapDocument
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode uap-core rules: %w", err)
	}
	if len(document.DeviceParsers) == 0 {
		return nil, fmt.Errorf("uap-core contains no device parsers")
	}
	rules := make([]Rule, 0, len(document.DeviceParsers))
	for _, item := range document.DeviceParsers {
		pattern := item.Regex
		if item.RegexFlag == "i" {
			pattern = "(?i)" + pattern
		}
		if _, err := regexp.Compile(pattern); err != nil {
			continue
		}
		rules = append(rules, Rule{
			Pattern:           pattern,
			Input:             "user_agent",
			BrandReplacement:  normalizeReplacement(item.BrandReplacement),
			ModelReplacement:  normalizeReplacement(item.ModelReplacement),
			DeviceReplacement: normalizeReplacement(item.DeviceReplacement),
			Confidence:        0.9,
		})
	}
	if len(rules) < 10 {
		return nil, fmt.Errorf("uap-core produced too few compatible device rules: %d", len(rules))
	}
	return rules, nil
}

func EncodeRules(rules []Rule) ([]byte, error) { return json.Marshal(rules) }

func normalizeReplacement(value string) string {
	return value
}
