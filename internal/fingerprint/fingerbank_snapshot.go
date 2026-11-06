package fingerprint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Fingerbank snapshot compilation.
//
// Raw rows may come from the bulk SQLite snapshot or from
// scripts/fingerprints/interrogate_fingerbank.py when only observed
// fingerprints are queried. Both emit fingerprints, vendor classes and the
// device hierarchy path only. Classification and normalisation stay in Go so a
// refreshed snapshot keeps the same semantics as the historical public snapshot
// parsed by FingerbankFromLegacy.

// FingerbankRawRecord is one row produced by the Python extractor. A row is the
// union of the fingerprints and vendor classes that point at the same device
// path, never a per-endpoint observation.
type FingerbankRawRecord struct {
	Fingerprints  []string `json:"fingerprints"`
	VendorClasses []string `json:"vendor_classes,omitempty"`
	DevicePath    string   `json:"device_path,omitempty"`
	Description   string   `json:"description,omitempty"`
	// Score is the Fingerbank confidence (0-100) when the row came from an
	// interrogate response. Bulk snapshots leave it zero and use the default.
	Score float64 `json:"score,omitempty"`
}

// FingerbankSnapshotStats describes what the compile step kept or dropped. It is
// written next to the bundle so a later review can tell a thin snapshot from a
// wrong table read.
type FingerbankSnapshotStats struct {
	RawRecords     int            `json:"raw_records"`
	Distinct       int            `json:"distinct_fingerprints"`
	EmittedRules   int            `json:"emitted_rules"`
	UnmappedRules  int            `json:"unmapped_rules"`
	UnmappedRate   float64        `json:"unmapped_rate"`
	DeviceTypes    map[string]int `json:"device_types"`
	OSFamilies     map[string]int `json:"os_families"`
	MalformedRows  int            `json:"malformed_rows"`
	LowScoreRows   int            `json:"low_score_rows"`
	Confidence     float64        `json:"confidence"`
	MinRules       int            `json:"min_rules"`
	MaxUnmappedPct float64        `json:"max_unmapped_rate"`
	MinScore       float64        `json:"min_score"`
}

// FingerbankCompileOptions bounds a build so a wrong table or an empty snapshot
// fails closed instead of replacing a working bundle with a thin one.
type FingerbankCompileOptions struct {
	Confidence      float64
	MinRules        int
	MaxUnmappedRate float64
	// MinScore drops interrogate rows below this Fingerbank score. Zero keeps
	// the built-in floor of 30.
	MinScore float64
	// MaxConfidence caps every rule so stronger project rules can still win.
	// Zero keeps the built-in ceiling of 0.9.
	MaxConfidence float64
}

const (
	fingerbankDefaultConfidence    = 0.84
	fingerbankDefaultMinRules      = 100
	fingerbankDefaultUnmappedCap   = 0.20
	fingerbankMinScore             = 30
	fingerbankDefaultMaxConfidence = 0.9
)

type fingerbankCandidate struct {
	options        string
	devicePath     string
	description    string
	deviceType     string
	osFamily       string
	score          float64
	vendors        map[string]struct{}
	vendorRequired bool
}

// CompileFingerbankSnapshot turns raw SQLite rows into the fingerbank-dhcp.json
// payload. The output is deterministic: the same raw input always produces the
// same bytes.
func CompileFingerbankSnapshot(raw []byte, options FingerbankCompileOptions) ([]byte, FingerbankSnapshotStats, error) {
	if options.Confidence <= 0 || options.Confidence > 1 {
		options.Confidence = fingerbankDefaultConfidence
	}
	if options.MinRules <= 0 {
		options.MinRules = fingerbankDefaultMinRules
	}
	if options.MaxUnmappedRate <= 0 || options.MaxUnmappedRate >= 1 {
		options.MaxUnmappedRate = fingerbankDefaultUnmappedCap
	}
	if options.MinScore <= 0 {
		options.MinScore = fingerbankMinScore
	}
	if options.MaxConfidence <= 0 || options.MaxConfidence > 1 {
		options.MaxConfidence = fingerbankDefaultMaxConfidence
	}
	stats := FingerbankSnapshotStats{
		DeviceTypes:    map[string]int{},
		OSFamilies:     map[string]int{},
		Confidence:     options.Confidence,
		MinRules:       options.MinRules,
		MaxUnmappedPct: options.MaxUnmappedRate,
		MinScore:       options.MinScore,
	}
	var records []FingerbankRawRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, stats, fmt.Errorf("decode fingerbank raw records: %w", err)
	}
	stats.RawRecords = len(records)

	// A DHCP options sequence is shared by many vendor classes. The API result
	// is for the exact pair, so keep competing devices separate by vendor.
	candidates := map[string]*fingerbankCandidate{}
	distinctOptions := map[string]struct{}{}
	for _, record := range records {
		// Provenance-only rows: a low interrogate score must not become a rule.
		if record.Score > 0 && record.Score < options.MinScore {
			stats.LowScoreRows++
			continue
		}
		deviceType, osFamily := normalizeFingerbankDevicePath(record.DevicePath, record.Description)
		for _, fingerprint := range record.Fingerprints {
			normalized := normalizeDHCPOptions(fingerprint)
			if normalized == "" {
				stats.MalformedRows++
				continue
			}
			distinctOptions[normalized] = struct{}{}
			vendors := record.VendorClasses
			if len(vendors) == 0 {
				vendors = []string{""}
			}
			for _, vendor := range vendors {
				vendor = strings.TrimSpace(vendor)
				key := normalized + "\x00" + strings.ToLower(vendor)
				candidate, ok := candidates[key]
				if !ok {
					candidate = &fingerbankCandidate{options: normalized, vendors: map[string]struct{}{}, vendorRequired: vendor != ""}
					candidates[key] = candidate
				}
				sameDevice := candidate.devicePath != "" && strings.EqualFold(strings.TrimSpace(candidate.devicePath), strings.TrimSpace(record.DevicePath))
				switch {
				case record.Score > candidate.score || (record.Score == candidate.score && len(record.DevicePath) > len(candidate.devicePath)):
					candidate.devicePath = record.DevicePath
					candidate.description = record.Description
					candidate.deviceType = deviceType
					candidate.osFamily = osFamily
					candidate.score = record.Score
				case !sameDevice:
					continue
				}
				if vendor != "" {
					candidate.vendors[vendor] = struct{}{}
				}
			}
		}
	}
	stats.Distinct = len(distinctOptions)

	// Merge agreeing vendors back into one rule while retaining every distinct
	// vendor-specific device result and its original score.
	grouped := map[string]*fingerbankCandidate{}
	for _, candidate := range candidates {
		if candidate.deviceType == "" && candidate.osFamily == "" {
			stats.UnmappedRules++
			continue
		}
		groupKey := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%g\x00%t", candidate.options, strings.ToLower(strings.TrimSpace(candidate.devicePath)), strings.ToLower(strings.TrimSpace(candidate.description)), candidate.deviceType, candidate.osFamily, candidate.score, candidate.vendorRequired)
		group, ok := grouped[groupKey]
		if !ok {
			copy := *candidate
			copy.vendors = map[string]struct{}{}
			group = &copy
			grouped[groupKey] = group
		}
		for vendor := range candidate.vendors {
			group.vendors[vendor] = struct{}{}
		}
	}
	items := make([]DHCPFingerprint, 0, len(grouped))
	for _, candidate := range grouped {
		vendors := make([]string, 0, len(candidate.vendors))
		for vendor := range candidate.vendors {
			vendors = append(vendors, vendor)
		}
		sort.Strings(vendors)
		items = append(items, DHCPFingerprint{
			RequestedOptions: candidate.options,
			VendorClasses:    vendors,
			VendorRequired:   candidate.vendorRequired,
			DeviceType:       candidate.deviceType,
			OSFamily:         candidate.osFamily,
			Description:      fingerbankDescription(candidate.devicePath, candidate.description),
			Confidence:       fingerbankRuleConfidence(candidate.score, options.Confidence, options.MaxConfidence),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].RequestedOptions != items[j].RequestedOptions {
			return items[i].RequestedOptions < items[j].RequestedOptions
		}
		if items[i].Description != items[j].Description {
			return items[i].Description < items[j].Description
		}
		return strings.Join(items[i].VendorClasses, "\x00") < strings.Join(items[j].VendorClasses, "\x00")
	})
	stats.EmittedRules = len(items)
	if len(candidates) > 0 {
		stats.UnmappedRate = float64(stats.UnmappedRules) / float64(len(candidates))
	}
	for _, item := range items {
		if item.DeviceType != "" {
			stats.DeviceTypes[item.DeviceType]++
		}
		if item.OSFamily != "" {
			stats.OSFamilies[item.OSFamily]++
		}
	}
	if stats.EmittedRules < options.MinRules {
		return nil, stats, fmt.Errorf("fingerbank snapshot produced too few rules: %d < %d", stats.EmittedRules, options.MinRules)
	}
	if stats.UnmappedRate > options.MaxUnmappedRate {
		return nil, stats, fmt.Errorf("fingerbank snapshot unmapped rate too high: %.2f > %.2f", stats.UnmappedRate, options.MaxUnmappedRate)
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return nil, stats, err
	}
	return encoded, stats, nil
}

// fingerbankDescription keeps the leaf of the device hierarchy; the full path is
// verbose and the evidence line only needs the model/OS label.
func fingerbankDescription(path, description string) string {
	path = strings.TrimSpace(path)
	if path != "" {
		parts := strings.Split(path, "/")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if strings.TrimSpace(description) != "" {
		return strings.TrimSpace(description)
	}
	return ""
}

// normalizeFingerbankDevicePath maps a Fingerbank device hierarchy onto the
// vocabulary the existing rules already use. The first path segment is the
// device family and is more reliable than keyword matching over the leaf.
func normalizeFingerbankDevicePath(path, description string) (string, string) {
	text := strings.ToLower(strings.TrimSpace(path + " " + description))
	segments := strings.Split(strings.ToLower(strings.TrimSpace(path)), "/")
	category := ""
	if len(segments) > 0 {
		category = strings.TrimSpace(segments[0])
	}
	osFamily := fingerbankOSFamily(text)
	detail := strings.ToLower(strings.TrimSpace(strings.Join(segments[1:], "/")))
	switch {
	case strings.HasPrefix(category, "phone, tablet or wearable"):
		if strings.Contains(detail, "ipad") {
			return "tablet", "iPadOS"
		}
		if strings.Contains(detail, "tablet") {
			return "tablet", osFamily
		}
		if strings.Contains(detail, "smartphone") || strings.Contains(detail, "iphone") || strings.HasPrefix(detail, "phone") || strings.Contains(detail, "/phone") || strings.Contains(detail, " phone") {
			return "mobile", osFamily
		}
		// The broad family includes phones, tablets and watches. Only a
		// model-specific Fingerbank leaf from a known product line narrows it.
		// A generic "Huawei Android" result must remain OS-only.
		if len(segments) >= 4 && strings.TrimSpace(segments[1]) == "generic android" && strings.TrimSpace(segments[2]) == "huawei android" {
			model := strings.TrimSpace(segments[len(segments)-1])
			switch {
			case strings.HasPrefix(model, "huawei matepad "), strings.HasPrefix(model, "huawei mediapad "):
				return "tablet", osFamily
			case strings.HasPrefix(model, "huawei mate "), strings.HasPrefix(model, "huawei nova "),
				strings.HasPrefix(model, "huawei pura "), strings.HasPrefix(model, "huawei pocket "),
				strings.HasPrefix(model, "huawei enjoy "):
				return "mobile", osFamily
			}
		}
		return "", osFamily
	case strings.HasPrefix(category, "router, access point"):
		if strings.Contains(detail, "access point") || strings.Contains(detail, "wireless ap") {
			return "access_point", ""
		}
		if strings.Contains(detail, "router") {
			return "router", ""
		}
		return "", ""
	case strings.HasPrefix(category, "router"):
		return "router", ""
	case strings.HasPrefix(category, "switch"):
		return "switch", ""
	case strings.HasPrefix(category, "firewall and security appliance"), strings.HasPrefix(category, "firewall"):
		return "firewall", ""
	case strings.HasPrefix(category, "voip device"):
		return "phone", osFamily
	case strings.HasPrefix(category, "internet of things"):
		return "iot", osFamily
	case strings.HasPrefix(category, "operating system"):
		// Windows and ChromeOS OS-only paths are desktop-class in the existing
		// rule vocabulary; other OS-only paths stay without a device type.
		if osFamily == "Windows" || osFamily == "ChromeOS" {
			return "desktop", osFamily
		}
		return "", osFamily
	case strings.Contains(text, "printer"):
		return "printer", osFamily
	case strings.Contains(text, "camera"):
		return "camera", osFamily
	case strings.Contains(text, "television") || strings.Contains(text, "smart tv") || strings.Contains(text, "roku") ||
		strings.Contains(text, "apple tv") || strings.Contains(text, "console") ||
		strings.Contains(text, "playstation") || strings.Contains(text, "xbox") || strings.Contains(text, "nintendo"):
		return "media_device", osFamily
	}
	// Fall back to the historical classifier for families the category list
	// does not cover; unknown paths stay empty instead of guessing.
	return normalizeFingerbankClass(path, description)
}

func fingerbankOSFamily(text string) string {
	switch {
	case strings.Contains(text, "windows"):
		return "Windows"
	case strings.Contains(text, "ipad"):
		return "iPadOS"
	case strings.Contains(text, "iphone") || strings.Contains(text, "ios"):
		return "iOS"
	case strings.Contains(text, "macos") || strings.Contains(text, "mac os") || strings.Contains(text, "macintosh"):
		return "macOS"
	case strings.Contains(text, "android"):
		return "Android"
	case strings.Contains(text, "harmony"):
		return "HarmonyOS"
	case strings.Contains(text, "chrome os") || strings.Contains(text, "chromebook"):
		return "ChromeOS"
	case strings.Contains(text, "tizen"):
		return "Tizen"
	case strings.Contains(text, "apple os"):
		return "Apple OS"
	case strings.Contains(text, "embedded linux"):
		return "Embedded Linux"
	case strings.Contains(text, "linux"):
		return "Linux"
	}
	return ""
}

// fingerbankRuleConfidence maps an interrogate score to the rule confidence.
// Scores below 30 are not compiled at all; the rest are clamped so a single
// vendor-class match can still reach the 0.9 ceiling used by the matcher.
func fingerbankRuleConfidence(score, fallback, ceiling float64) float64 {
	if score <= 0 {
		return fallback
	}
	value := score / 100
	if value < 0.5 {
		value = 0.5
	}
	if value > ceiling {
		value = ceiling
	}
	return value
}
