package fingerprint

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed data/oui.csv
var embeddedOUI []byte

//go:embed data/device_rules.json
var embeddedRules []byte

//go:embed data/brand_aliases.json
var embeddedBrandAliases []byte

const EmbeddedVersion = "embedded-2026-08"

type Result struct {
	Vendor               string   `json:"vendor,omitempty"`
	Brand                string   `json:"brand,omitempty"`
	Model                string   `json:"model,omitempty"`
	DeviceType           string   `json:"device_type,omitempty"`
	OSFamily             string   `json:"os_family,omitempty"`
	Confidence           float64  `json:"recognition_confidence"`
	VendorConfidence     float64  `json:"vendor_confidence"`
	BrandConfidence      float64  `json:"brand_confidence"`
	ModelConfidence      float64  `json:"model_confidence"`
	DeviceTypeConfidence float64  `json:"device_type_confidence"`
	OSFamilyConfidence   float64  `json:"os_family_confidence"`
	Source               string   `json:"recognition_source,omitempty"`
	Version              string   `json:"fingerprint_version,omitempty"`
	RandomizedMAC        bool     `json:"randomized_mac"`
	Conflict             bool     `json:"recognition_conflict"`
	Evidence             []string `json:"recognition_evidence,omitempty"`
}

type Signals struct {
	MAC                  string
	UserAgents           []string
	DHCPVendorClass      string
	DHCPRequestedOptions string
	Hostnames            []string
	Software             []string
	Hints                []string
}

type Rule struct {
	Pattern           string  `json:"pattern"`
	Input             string  `json:"input,omitempty"`
	Brand             string  `json:"brand,omitempty"`
	Model             string  `json:"model,omitempty"`
	DeviceType        string  `json:"device_type,omitempty"`
	OSFamily          string  `json:"os_family,omitempty"`
	BrandReplacement  string  `json:"brand_replacement,omitempty"`
	ModelReplacement  string  `json:"model_replacement,omitempty"`
	DeviceReplacement string  `json:"device_replacement,omitempty"`
	Confidence        float64 `json:"confidence"`
	compiled          *regexp.Regexp
}

type Library struct {
	version string
	ouis    map[string]string
	rules   []Rule
	dhcp    map[string][]DHCPFingerprint
	aliases map[string]string
}

var (
	defaultMu      sync.RWMutex
	defaultLibrary = MustLoad(EmbeddedVersion, embeddedOUI, embeddedRules)
)

func Default() *Library {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultLibrary
}

func SetDefault(library *Library) {
	if library == nil {
		return
	}
	defaultMu.Lock()
	defaultLibrary = library
	defaultMu.Unlock()
}

func MustLoad(version string, ouiCSV, rulesJSON []byte) *Library {
	library, err := Load(version, ouiCSV, rulesJSON)
	if err != nil {
		panic(err)
	}
	return library
}

func Load(version string, ouiCSV, rulesJSON []byte) (*Library, error) {
	return LoadWithData(version, ouiCSV, rulesJSON, []byte("[]"), embeddedBrandAliases)
}

func LoadWithData(version string, ouiCSV, rulesJSON, fingerbankJSON, aliasesJSON []byte) (*Library, error) {
	ouis, err := parseOUI(ouiCSV)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("decode device rules: %w", err)
	}
	for index := range rules {
		if strings.TrimSpace(rules[index].Pattern) == "" {
			return nil, fmt.Errorf("device rule %d has empty pattern", index)
		}
		compiled, err := regexp.Compile("(?i)" + rules[index].Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile device rule %d: %w", index, err)
		}
		rules[index].compiled = compiled
	}
	var fingerprints []DHCPFingerprint
	if err := json.Unmarshal(fingerbankJSON, &fingerprints); err != nil {
		return nil, fmt.Errorf("decode Fingerbank data: %w", err)
	}
	dhcp := map[string][]DHCPFingerprint{}
	for _, item := range fingerprints {
		if item.RequestedOptions != "" {
			dhcp[normalizeDHCPOptions(item.RequestedOptions)] = append(dhcp[normalizeDHCPOptions(item.RequestedOptions)], item)
		}
	}
	aliases := map[string]string{}
	if err := json.Unmarshal(aliasesJSON, &aliases); err != nil {
		return nil, fmt.Errorf("decode brand aliases: %w", err)
	}
	return &Library{version: version, ouis: ouis, rules: rules, dhcp: dhcp, aliases: aliases}, nil
}

func (l *Library) Version() string { return l.version }

func (l *Library) Identify(mac string, values ...string) Result {
	return l.IdentifySignals(Signals{MAC: mac, UserAgents: values, Hints: values})
}

func (l *Library) IdentifySignals(signals Signals) Result {
	mac := signals.MAC
	result := Result{Version: l.version, RandomizedMAC: IsRandomizedMAC(mac)}
	if !result.RandomizedMAC {
		prefix := normalizeMAC(mac)
		if len(prefix) >= 6 {
			for _, size := range []int{9, 7, 6} {
				if len(prefix) >= size && l.ouis[prefix[:size]] != "" {
					result.Vendor = l.ouis[prefix[:size]]
					break
				}
			}
			if result.Vendor != "" {
				result.Source = "ieee_oui"
				result.Confidence = 0.9
				result.VendorConfidence = 0.9
				result.Evidence = append(result.Evidence, "IEEE OUI: "+result.Vendor)
			}
		}
	}
	joined := strings.Join(append(append(append([]string{}, signals.UserAgents...), signals.Hostnames...), append(signals.Software, signals.Hints...)...), " ")
	userAgents := strings.Join(signals.UserAgents, " ")
	for _, rule := range l.rules {
		input := joined
		if rule.Input == "user_agent" {
			input = userAgents
		}
		match := rule.compiled.FindStringSubmatchIndex(input)
		if match == nil {
			continue
		}
		if value := expandRule(rule.compiled, input, match, firstNonEmpty(rule.BrandReplacement, rule.Brand)); value != "" {
			result.Brand = value
			result.BrandConfidence = rule.Confidence
		}
		if value := expandRule(rule.compiled, input, match, firstNonEmpty(rule.ModelReplacement, rule.Model, rule.DeviceReplacement)); value != "" {
			result.Model = value
			result.ModelConfidence = rule.Confidence
		}
		if rule.DeviceType != "" {
			result.DeviceType = rule.DeviceType
			result.DeviceTypeConfidence = rule.Confidence
		}
		if rule.OSFamily != "" {
			result.OSFamily = rule.OSFamily
			result.OSFamilyConfidence = rule.Confidence
		}
		if rule.Confidence >= result.Confidence || result.Source == "ieee_oui" {
			result.Confidence = rule.Confidence
			result.Source = "device_rule"
		}
		result.Evidence = append(result.Evidence, "设备规则: "+rule.Pattern)
		break
	}
	if candidates := l.dhcp[normalizeDHCPOptions(signals.DHCPRequestedOptions)]; len(candidates) > 0 {
		candidate, ok := bestDHCPFingerprint(candidates, signals.DHCPVendorClass)
		if ok {
			if result.OSFamily != "" && candidate.OSFamily != "" && !strings.EqualFold(result.OSFamily, candidate.OSFamily) {
				result.Conflict = true
			}
			if result.DeviceType == "" {
				result.DeviceType = candidate.DeviceType
				result.DeviceTypeConfidence = candidate.Confidence
			}
			if result.OSFamily == "" {
				result.OSFamily = candidate.OSFamily
				result.OSFamilyConfidence = candidate.Confidence
			}
			if result.Source == "" || result.Source == "ieee_oui" {
				result.Source = "fingerbank_dhcp"
				result.Confidence = candidate.Confidence
			}
			result.Evidence = append(result.Evidence, "Fingerbank DHCP: "+candidate.Description)
		}
	}
	if result.Brand != "" {
		if normalized := l.normalizedBrand(result.Brand); normalized != "" {
			result.Brand = normalized
		}
	}
	return result
}

func bestDHCPFingerprint(items []DHCPFingerprint, vendorClass string) (DHCPFingerprint, bool) {
	vendorClass = strings.ToLower(strings.TrimSpace(vendorClass))
	for _, item := range items {
		for _, vendor := range item.VendorClasses {
			if vendorClass != "" && strings.EqualFold(strings.TrimSpace(vendor), vendorClass) {
				item.Confidence = 0.9
				return item, true
			}
		}
	}
	if len(items) == 1 {
		return items[0], true
	}
	return DHCPFingerprint{}, false
}

func parseOUI(data []byte) (map[string]string, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("decode OUI CSV: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("OUI CSV contains no assignments")
	}
	assignmentIndex, organizationIndex := -1, -1
	for index, value := range records[0] {
		switch strings.TrimSpace(value) {
		case "Assignment":
			assignmentIndex = index
		case "Organization Name":
			organizationIndex = index
		}
	}
	if assignmentIndex < 0 || organizationIndex < 0 {
		return nil, fmt.Errorf("OUI CSV has unsupported headers")
	}
	result := map[string]string{}
	for _, record := range records[1:] {
		if assignmentIndex >= len(record) || organizationIndex >= len(record) {
			continue
		}
		prefix := normalizeMAC(record[assignmentIndex])
		if len(prefix) >= 6 && strings.TrimSpace(record[organizationIndex]) != "" {
			result[prefix] = strings.TrimSpace(record[organizationIndex])
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("OUI CSV contains no assignments")
	}
	return result, nil
}

func IsRandomizedMAC(mac string) bool {
	normalized := normalizeMAC(mac)
	if len(normalized) < 2 {
		return false
	}
	var first byte
	if _, err := fmt.Sscanf(normalized[:2], "%02X", &first); err != nil {
		return false
	}
	return first&0x02 != 0
}

func normalizeMAC(value string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.TrimSpace(value)))
}

func expandRule(compiled *regexp.Regexp, input string, match []int, replacement string) string {
	if replacement == "" {
		return ""
	}
	return strings.TrimSpace(string(compiled.ExpandString(nil, replacement, input, match)))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (l *Library) normalizedBrand(vendor string) string {
	lower := strings.ToLower(vendor)
	if brand := l.aliases[lower]; brand != "" {
		return brand
	}
	brands := map[string]string{"apple": "Apple", "samsung": "Samsung", "xiaomi": "Xiaomi", "vmware": "VMware", "microsoft": "Microsoft", "google": "Google", "parallels": "Parallels"}
	keys := make([]string, 0, len(brands))
	for key := range brands {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if strings.Contains(lower, key) {
			return brands[key]
		}
	}
	return ""
}
