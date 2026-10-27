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

//go:embed data/domain_signatures.json
var embeddedDomainSignatures []byte

const EmbeddedVersion = "embedded-2026-10.2"

var macHostnameClue = regexp.MustCompile(`(?i)(^|[-_. ])(mac(book|intosh)?|imac)($|[-_. 0-9])`)

type Result struct {
	SourceMatches        []SourceMatch `json:"source_matches,omitempty"`
	EvidenceRefs         []EvidenceRef `json:"evidence_refs,omitempty"`
	Diagnostics          Diagnostics   `json:"recognition_diagnostics"`
	Vendor               string        `json:"vendor,omitempty"`
	Brand                string        `json:"brand,omitempty"`
	Model                string        `json:"model,omitempty"`
	DeviceType           string        `json:"device_type,omitempty"`
	OSFamily             string        `json:"os_family,omitempty"`
	Confidence           float64       `json:"recognition_confidence"`
	VendorConfidence     float64       `json:"vendor_confidence"`
	BrandConfidence      float64       `json:"brand_confidence"`
	ModelConfidence      float64       `json:"model_confidence"`
	DeviceTypeConfidence float64       `json:"device_type_confidence"`
	OSFamilyConfidence   float64       `json:"os_family_confidence"`
	Source               string        `json:"recognition_source,omitempty"`
	Version              string        `json:"fingerprint_version,omitempty"`
	RandomizedMAC        bool          `json:"randomized_mac"`
	Conflict             bool          `json:"recognition_conflict"`
	ConflictDimensions   []string      `json:"conflict_dimensions,omitempty"`
	Evidence             []string      `json:"recognition_evidence,omitempty"`
}

type Signals struct {
	ProtocolFields       map[string][]string
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
	catalog     *Catalog
	version     string
	ouis        map[string]string
	rules       []Rule
	ruleIndex   map[string][]int
	dhcp        map[string][]DHCPFingerprint
	aliases     map[string]string
	domains     []DomainSignature
	domainIndex *domainNode
}

var (
	defaultMu      sync.RWMutex
	defaultLibrary = mustLoadEmbedded()
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
	return LoadWithDomainData(version, ouiCSV, rulesJSON, fingerbankJSON, aliasesJSON, nil)
}

func LoadWithDomainData(version string, ouiCSV, rulesJSON, fingerbankJSON, aliasesJSON, domainJSON []byte) (*Library, error) {
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
	ruleIndex := make(map[string][]int)
	for index, rule := range rules {
		ruleIndex[rule.Input] = append(ruleIndex[rule.Input], index)
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
	domains, domainIndex, err := parseDomainSignatures(domainJSON)
	if err != nil {
		return nil, err
	}
	return &Library{version: version, ouis: ouis, rules: rules, ruleIndex: ruleIndex, dhcp: dhcp, aliases: aliases, domains: domains, domainIndex: domainIndex}, nil
}

func (l *Library) Version() string { return l.version }

func (l *Library) Identify(mac string, values ...string) Result {
	return l.IdentifySignals(Signals{MAC: mac, Hints: values})
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
	// A device that reports its sysObjectID names its own vendor. This outranks
	// a MAC OUI, which often identifies the NIC vendor rather than the device
	// brand, but it never confirms a model or a physical role.
	if result.Vendor == "" {
		for _, oid := range signals.ProtocolFields["snmp_sysoid"] {
			vendor, confidence, ok := LookupSNMPVendor(oid)
			if !ok {
				continue
			}
			result.Vendor = vendor
			result.VendorConfidence = confidence
			result.Source = "snmp_sysoid"
			result.Evidence = append(result.Evidence, "SNMP sysObjectID: "+strings.TrimSpace(oid)+" → "+vendor)
			break
		}
	}
	// The DHCP vendor class is self-reported like the hostname (for example
	// "HP LaserJet" or "HUAWEI:openharmony:<model>"), so rules see it too.
	joined := strings.Join(append(append(append([]string{}, signals.Hostnames...), append(signals.Software, signals.Hints...)...), signals.DHCPVendorClass), " ")
	// Rules may target one structured field (ssdp_model, dhcp_vendor_class, ...)
	// or fall back to the concatenated self-reported text. Field-scoped matches
	// outrank the concatenated blob, and the highest-confidence match wins
	// instead of the first one in file order.
	// A verified model code outranks regular-expression rules: the code and the
	// product name share no textual similarity, so no rule can derive one from
	// the other. Rules may still contribute an operating system.
	modelEntry, modelCode, hasModel := l.modelFromSignals(signals, result.Vendor)
	if hasModel {
		result.Brand = modelEntry.Brand
		result.BrandConfidence = modelEntry.Confidence
		result.Model = modelEntry.Model
		result.ModelConfidence = modelEntry.Confidence
		if modelEntry.DeviceType != "" {
			result.DeviceType = modelEntry.DeviceType
			result.DeviceTypeConfidence = modelEntry.Confidence
		}
		result.Source = "model_catalog"
		result.Confidence = modelEntry.Confidence
		result.Evidence = append(result.Evidence, "型号库: "+modelCode+" → "+modelEntry.Model)
	}
	matches, evaluatedRules := l.matchRules(signals, joined)
	result.Diagnostics.CandidateRules = evaluatedRules
	if len(matches) > 0 {
		if hasModel {
			applyRuleExtras(&result, expandRuleValues(matches[0]))
		} else {
			applyRuleMatch(&result, matches[0], expandRuleValues(matches[0]))
		}
		for _, extra := range matches[1:] {
			for _, dimension := range ruleMatchConflictDimensions(result, extra) {
				result.Conflict = true
				result.ConflictDimensions = appendConflictDimension(result.ConflictDimensions, dimension)
			}
		}
	}
	// A device-reported Android DHCP class still identifies its OS when a more
	// specific hostname rule wins brand and model selection.
	if result.OSFamily == "" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(signals.DHCPVendorClass)), "android-dhcp-") {
		result.OSFamily = "Android"
		result.OSFamilyConfidence = .82
		result.Evidence = append(result.Evidence, "DHCP vendor class: Android")
	}
	// Darwin alone does not distinguish Apple's operating systems. A Mac hostname
	// corroborates only a tentative macOS clue; neither signal establishes brand.
	// Keep this standard-signal fallback available with installed offline bundles.
	if result.OSFamily == "" && strings.EqualFold(strings.TrimSpace(signals.DHCPVendorClass), "darwin") {
		for _, hostname := range signals.Hostnames {
			if !macHostnameClue.MatchString(hostname) {
				continue
			}
			result.OSFamily, result.OSFamilyConfidence = "macOS", .65
			if result.Confidence < .65 {
				result.Confidence = .65
			}
			if result.Source == "" || result.Source == "ieee_oui" {
				result.Source = "dhcp_hostname_hint"
			}
			result.Evidence = append(result.Evidence, "macOS 推测: DHCP vendor class darwin + Mac 主机名 "+hostname)
			break
		}
	}
	if candidates := l.dhcp[normalizeDHCPOptions(signals.DHCPRequestedOptions)]; len(candidates) > 0 {
		candidate, ok := bestDHCPFingerprint(candidates, signals.DHCPVendorClass)
		if ok {
			if result.OSFamily != "" && candidate.OSFamily != "" && !strings.EqualFold(result.OSFamily, candidate.OSFamily) {
				result.Conflict = true
				result.ConflictDimensions = appendConflictDimension(result.ConflictDimensions, "os_family")
			}
			if result.DeviceType == "" {
				result.DeviceType = candidate.DeviceType
				result.DeviceTypeConfidence = candidate.Confidence
			}
			if result.OSFamily == "" {
				result.OSFamily = candidate.OSFamily
				result.OSFamilyConfidence = candidate.Confidence
			}
			if result.Source == "" || result.Source == "ieee_oui" || result.Source == "dhcp_hostname_hint" {
				result.Source = "fingerbank_dhcp"
				result.Confidence = candidate.Confidence
			}
			result.Evidence = append(result.Evidence, "Fingerbank DHCP: "+candidate.Description)
		}
	}
	if result.DeviceType == "" && result.Vendor != "" {
		if deviceType, confidence, ok := LookupVendorPrior(result.Vendor); ok {
			result.DeviceType = deviceType
			result.DeviceTypeConfidence = confidence
			result.Evidence = append(result.Evidence, "厂商类型先验: "+result.Vendor+" → "+deviceType)
		}
	}
	if result.Brand != "" {
		if normalized := l.normalizedBrand(result.Brand); normalized != "" {
			result.Brand = normalized
		}
	}
	sourceMatches, catalogEvaluated := l.Catalog().MatchWithStats(catalogSignalValues(signals))
	result.Diagnostics.CandidateRules += catalogEvaluated
	applySourceMatches(&result, sourceMatches)
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

// ruleMatch is one rule hit against one input value.
type ruleMatch struct {
	rule        *Rule
	input       string // "" means the concatenated self-reported text
	value       string
	loc         []int
	specificity int
	order       int
}

type ruleValues struct {
	brand      string
	model      string
	deviceType string
	osFamily   string
}

func (l *Library) matchRules(signals Signals, joined string) ([]ruleMatch, int) {
	out := make([]ruleMatch, 0, 4)
	evaluated := 0
	inputs := make([]string, 0, len(l.ruleIndex))
	for input := range l.ruleIndex {
		if input != "user_agent" {
			inputs = append(inputs, input)
		}
	}
	sort.Strings(inputs)
	for _, input := range inputs {
		values, specificity := ruleInputValues(signals, joined, input)
		if len(values) == 0 {
			continue
		}
		for _, index := range l.ruleIndex[input] {
			rule := &l.rules[index]
			if rule.Input == "user_agent" {
				// UA identifies a client/runtime, not a physical endpoint. Keep the
				// parser rules in the offline bundle for technical inspection, but
				// never promote their brand/model/device result into the endpoint
				// profile without an independent standard device signal.
				continue
			}
			for _, value := range values {
				if strings.TrimSpace(value) == "" {
					continue
				}
				evaluated++
				loc := rule.compiled.FindStringSubmatchIndex(value)
				if loc == nil {
					continue
				}
				out = append(out, ruleMatch{rule: rule, input: rule.Input, value: value, loc: loc, specificity: specificity, order: index})
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].specificity != out[j].specificity {
			return out[i].specificity > out[j].specificity
		}
		if out[i].rule.Confidence != out[j].rule.Confidence {
			return out[i].rule.Confidence > out[j].rule.Confidence
		}
		return out[i].order < out[j].order
	})
	return out, evaluated
}

// ruleInputValues returns the values a rule is allowed to inspect. Rules without
// an explicit input keep the historical behaviour of matching the concatenated
// self-reported text; rules declaring an input never see other fields.
func ruleInputValues(signals Signals, joined, input string) ([]string, int) {
	switch input {
	case "":
		return []string{joined}, 0
	case "hostname":
		return signals.Hostnames, 1
	case "dhcp_vendor_class":
		return nonEmptyValue(signals.DHCPVendorClass), 1
	default:
		return signals.ProtocolFields[input], 1
	}
}

func nonEmptyValue(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return []string{value}
}

func expandRuleValues(match ruleMatch) ruleValues {
	rule := match.rule
	return ruleValues{
		brand:      expandRule(rule.compiled, match.value, match.loc, firstNonEmpty(rule.BrandReplacement, rule.Brand)),
		model:      expandRule(rule.compiled, match.value, match.loc, firstNonEmpty(rule.ModelReplacement, rule.Model, rule.DeviceReplacement)),
		deviceType: strings.TrimSpace(rule.DeviceType),
		osFamily:   strings.TrimSpace(rule.OSFamily),
	}
}

// applyRuleExtras lets rules contribute only when a verified model code already
// established brand, model and device type.
func applyRuleExtras(result *Result, values ruleValues) {
	if values.osFamily != "" && result.OSFamily == "" {
		result.OSFamily = values.osFamily
		result.OSFamilyConfidence = .85
	}
	if values.deviceType != "" && result.DeviceType == "" {
		result.DeviceType = values.deviceType
		result.DeviceTypeConfidence = .6
	}
}

func applyRuleMatch(result *Result, match ruleMatch, values ruleValues) {
	if values.brand != "" {
		result.Brand = values.brand
		result.BrandConfidence = match.rule.Confidence
	}
	if values.model != "" {
		result.Model = values.model
		result.ModelConfidence = match.rule.Confidence
	}
	if values.deviceType != "" {
		result.DeviceType = values.deviceType
		result.DeviceTypeConfidence = match.rule.Confidence
	}
	if values.osFamily != "" {
		result.OSFamily = values.osFamily
		result.OSFamilyConfidence = match.rule.Confidence
	}
	result.Confidence = match.rule.Confidence
	result.Source = "device_rule"
	if match.input != "" {
		result.Source = "device_rule:" + match.input
	}
	result.Evidence = append(result.Evidence, "设备规则: "+match.rule.Pattern)
}

// ruleMatchConflicts reports a high-confidence disagreement between the winning
// rule and a lower-ranked rule without letting the loser overwrite any field.
func ruleMatchConflicts(result Result, match ruleMatch) bool {
	return len(ruleMatchConflictDimensions(result, match)) > 0
}

func ruleMatchConflictDimensions(result Result, match ruleMatch) []string {
	if match.rule.Confidence < .85 {
		return nil
	}
	values := expandRuleValues(match)
	conflicts := []string{}
	for _, item := range []struct{ field, current, candidate string }{
		{"brand", result.Brand, values.brand},
		{"device_type", result.DeviceType, values.deviceType},
		{"os_family", result.OSFamily, values.osFamily},
	} {
		if item.current != "" && item.candidate != "" && !strings.EqualFold(item.current, item.candidate) {
			conflicts = append(conflicts, item.field)
		}
	}
	return conflicts
}

func appendConflictDimension(current []string, field string) []string {
	for _, present := range current {
		if present == field {
			return current
		}
	}
	return append(current, field)
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

func mustLoadEmbedded() *Library {
	if err := VerifyCatalogProvenance(embeddedCatalog, embeddedProvenance); err != nil {
		panic(err)
	}
	l, err := LoadWithDomainData(EmbeddedVersion, embeddedOUI, embeddedRules, []byte("[]"), embeddedBrandAliases, embeddedDomainSignatures)
	if err != nil {
		panic(err)
	}
	if err := l.LoadCatalog(embeddedCatalog); err != nil {
		panic(err)
	}
	return l
}
