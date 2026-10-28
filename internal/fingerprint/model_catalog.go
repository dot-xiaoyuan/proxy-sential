package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed data/model-catalog.json
var embeddedModelCatalog []byte

// ModelEntry is a verified mapping from a vendor model code to the product name
// it is sold under. This is the layer a regular expression cannot provide: the
// code and the marketing name share no textual similarity.
type ModelEntry struct {
	Brand         string  `json:"brand"`
	Model         string  `json:"model"`
	ProductFamily string  `json:"product_family,omitempty"`
	DeviceType    string  `json:"device_type"`
	Confidence    float64 `json:"confidence"`
}

// ModelCatalog resolves model codes. Lookup is exact-first, then longest-prefix
// so that a variant suffix ("SM-G991B/DS") still resolves to its family.
type ModelCatalog struct {
	Version   string                `json:"version"`
	Source    string                `json:"source"`
	SourceURL string                `json:"source_url"`
	License   string                `json:"license"`
	Entries   map[string]ModelEntry `json:"entries"`
	keys      []string
}

var modelCatalogState = struct {
	sync.RWMutex
	catalog *ModelCatalog
}{catalog: mustLoadModelCatalog(embeddedModelCatalog)}

// ParseModelCatalog validates a model catalog.
func ParseModelCatalog(data []byte) (*ModelCatalog, error) {
	var catalog ModelCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("decode model catalog: %w", err)
	}
	if strings.TrimSpace(catalog.Version) == "" || strings.TrimSpace(catalog.Source) == "" {
		return nil, fmt.Errorf("model catalog requires a version and source")
	}
	if len(catalog.Entries) == 0 {
		return nil, fmt.Errorf("model catalog contains no entries")
	}
	clean := make(map[string]ModelEntry, len(catalog.Entries))
	for code, entry := range catalog.Entries {
		key := strings.ToUpper(strings.TrimSpace(code))
		entry.Brand = strings.TrimSpace(entry.Brand)
		entry.Model = strings.TrimSpace(entry.Model)
		entry.ProductFamily = strings.TrimSpace(entry.ProductFamily)
		entry.DeviceType = strings.TrimSpace(entry.DeviceType)
		if len(key) < 5 || entry.Brand == "" || entry.Model == "" {
			return nil, fmt.Errorf("model catalog entry %q is invalid", code)
		}
		if entry.Confidence <= 0 || entry.Confidence > .95 {
			return nil, fmt.Errorf("model catalog entry %q confidence must be within (0, 0.95]", code)
		}
		clean[key] = entry
	}
	catalog.Entries = clean
	catalog.keys = make([]string, 0, len(clean))
	for key := range clean {
		catalog.keys = append(catalog.keys, key)
	}
	// Longest key first so "DS-2CD2143G0-I" beats a shorter family prefix.
	sort.Slice(catalog.keys, func(i, j int) bool {
		if len(catalog.keys[i]) != len(catalog.keys[j]) {
			return len(catalog.keys[i]) > len(catalog.keys[j])
		}
		return catalog.keys[i] < catalog.keys[j]
	})
	return &catalog, nil
}

// SetModelCatalog swaps the process-wide catalog, mainly for bundles and tests.
func SetModelCatalog(catalog *ModelCatalog) {
	if catalog == nil {
		return
	}
	modelCatalogState.Lock()
	modelCatalogState.catalog = catalog
	modelCatalogState.Unlock()
}

// LookupModel resolves an exact model code or a longer variant that starts with
// a known code.
func LookupModel(code string) (brand, model, deviceType string, confidence float64, ok bool) {
	needle := strings.ToUpper(strings.TrimSpace(code))
	if needle == "" {
		return "", "", "", 0, false
	}
	modelCatalogState.RLock()
	catalog := modelCatalogState.catalog
	modelCatalogState.RUnlock()
	if catalog == nil {
		return "", "", "", 0, false
	}
	if entry, found := catalog.Entries[needle]; found {
		return entry.Brand, entry.Model, entry.DeviceType, entry.Confidence, true
	}
	for _, key := range catalog.keys {
		if strings.HasPrefix(needle, key) && modelTokenBoundary(needle, len(key)) {
			entry := catalog.Entries[key]
			return entry.Brand, entry.Model, entry.DeviceType, entry.Confidence, true
		}
	}
	return "", "", "", 0, false
}

// lookupModelInText scans a free-form value for an embedded model code.
func lookupModelInText(value string) (ModelEntry, string, bool) {
	upper := strings.ToUpper(strings.TrimSpace(value))
	if upper == "" {
		return ModelEntry{}, "", false
	}
	modelCatalogState.RLock()
	catalog := modelCatalogState.catalog
	modelCatalogState.RUnlock()
	if catalog == nil {
		return ModelEntry{}, "", false
	}
	for _, key := range catalog.keys {
		if containsModelToken(upper, key) {
			return catalog.Entries[key], key, true
		}
	}
	return ModelEntry{}, "", false
}

func containsModelToken(value, key string) bool {
	for offset := 0; offset < len(value); {
		index := strings.Index(value[offset:], key)
		if index < 0 {
			return false
		}
		index += offset
		if (index == 0 || modelTokenBoundary(value, index-1)) && modelTokenBoundary(value, index+len(key)) {
			return true
		}
		offset = index + 1
	}
	return false
}

// Separators allow explicit variants such as SM-G991B/DS. Adjacent letters or
// digits denote a different code rather than a matching product substring.
func modelTokenBoundary(value string, at int) bool {
	if at >= len(value) {
		return true
	}
	c := value[at]
	return !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 128)
}

// modelCandidates returns values that may embed a model code, excluding user
// agents. UA strings carry model codes but describe a client runtime, so they
// are only consulted when an independent vendor signal corroborates the brand.
// Structured protocol self-report comes first: the device names its own
// product model there, while a hostname only hints at it.
func modelCandidates(signals Signals) []string {
	out := make([]string, 0, 10)
	out = append(out, signals.ProtocolFields["ssdp_model"]...)
	out = append(out, signals.ProtocolFields["snmp_model"]...)
	out = append(out, signals.ProtocolFields["dns_sd_model"]...)
	out = append(out, signals.ProtocolFields["mdns_model"]...)
	for _, field := range []string{"printer_make_and_model", "onvif_model", "wsd_model", "mqtt_model", "coap_device_type", "bacnet_model", "cdp_platform"} {
		out = append(out, signals.ProtocolFields[field]...)
	}
	out = append(out, signals.Hostnames...)
	out = append(out, signals.Hints...)
	out = append(out, signals.Software...)
	out = append(out, nonEmptyValue(signals.DHCPVendorClass)...)
	return out
}

// modelsFromSignals resolves model codes, allowing user-agent codes only when
// the MAC OUI vendor normalizes to the same brand.
type modelCandidate struct {
	entry ModelEntry
	code  string
	field string
}

func (l *Library) modelsFromSignals(signals Signals, vendor string) []modelCandidate {
	out := []modelCandidate{}
	seen := map[string]bool{}
	add := func(entry ModelEntry, code, field string) {
		key := strings.ToLower(entry.Brand + "/" + entry.Model)
		if !seen[key] && len(out) < 16 {
			out = append(out, modelCandidate{entry, code, field})
			seen[key] = true
		}
	}
	for _, value := range modelCandidates(signals) {
		for _, candidate := range lookupModelsInText(value) {
			add(candidate.entry, candidate.code, modelCandidateField(signals, value))
		}
	}
	// Corroborated client hints remain weaker than device self-report.
	if len(out) == 0 {
		want := l.normalizedBrand(vendor)
		for _, ua := range signals.UserAgents {
			if entry, code, ok := lookupModelInText(ua); ok && want != "" && strings.EqualFold(entry.Brand, want) {
				entry.Confidence = minFloat(entry.Confidence, .80)
				add(entry, code, "user_agent")
			}
		}
	}
	return out
}

func lookupModelsInText(value string) []modelCandidate {
	upper := strings.ToUpper(strings.TrimSpace(value))
	modelCatalogState.RLock()
	catalog := modelCatalogState.catalog
	modelCatalogState.RUnlock()
	if catalog == nil || upper == "" {
		return nil
	}
	out := []modelCandidate{}
	for _, key := range catalog.keys {
		if !containsModelToken(upper, key) {
			continue
		}
		overlap := false
		for _, candidate := range out {
			if strings.HasPrefix(candidate.code, key) {
				overlap = true
				break
			}
		}
		if !overlap {
			out = append(out, modelCandidate{entry: catalog.Entries[key], code: key})
		}
		if len(out) == 16 {
			break
		}
	}
	return out
}

func modelCandidateField(signals Signals, value string) string {
	for _, field := range []string{"ssdp_model", "snmp_model", "dns_sd_model", "mdns_model", "printer_make_and_model", "onvif_model", "wsd_model", "mqtt_model", "coap_device_type", "bacnet_model", "cdp_platform"} {
		for _, v := range signals.ProtocolFields[field] {
			if v == value {
				return field
			}
		}
	}
	for _, v := range signals.Hostnames {
		if v == value {
			return "hostname"
		}
	}
	if value == signals.DHCPVendorClass {
		return "dhcp_vendor_class"
	}
	for _, v := range signals.Software {
		if v == value {
			return "software_name"
		}
	}
	return "device_hint"
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func mustLoadModelCatalog(data []byte) *ModelCatalog {
	catalog, err := ParseModelCatalog(data)
	if err != nil {
		panic(err)
	}
	return catalog
}
