package fingerprint

import "strings"

// Candidates and dimension evidence contain conclusions and references only;
// observed protocol values remain in their authoritative standard event.
type ProductCandidate struct {
	Family     string  `json:"family,omitempty"`
	Vendor     string  `json:"vendor,omitempty"`
	Brand      string  `json:"brand,omitempty"`
	Model      string  `json:"model,omitempty"`
	DeviceType string  `json:"device_type,omitempty"`
	Source     string  `json:"source"`
	Field      string  `json:"field,omitempty"`
	Confidence float64 `json:"confidence"`
}

type DimensionEvidence struct {
	Dimension  string        `json:"dimension"`
	Value      string        `json:"value"`
	Layer      string        `json:"layer"`
	Field      string        `json:"field,omitempty"`
	RuleID     string        `json:"rule_id,omitempty"`
	Confidence float64       `json:"confidence"`
	Refs       []EvidenceRef `json:"refs,omitempty"`
	matchValue string
}

func addProductCandidate(result *Result, candidate ProductCandidate) {
	for _, prior := range result.ProductCandidates {
		if prior == candidate {
			return
		}
	}
	if len(result.ProductCandidates) < 16 {
		result.ProductCandidates = append(result.ProductCandidates, candidate)
	}
}

func recordDimensionEvidence(result *Result, layer, field, ruleID string, values ruleValues, confidence float64) {
	for _, pair := range [][2]string{{"brand", values.brand}, {"product_family", values.productFamily}, {"model", values.model}, {"device_type", values.deviceType}, {"os_family", values.osFamily}} {
		if pair[1] == "" || strings.Contains(pair[1], "$") {
			continue
		}
		entry := DimensionEvidence{Dimension: pair[0], Value: pair[1], Layer: layer, Field: field, RuleID: ruleID, Confidence: confidence}
		duplicate := false
		for _, prior := range result.DimensionEvidence {
			if prior.Dimension == entry.Dimension && prior.Value == entry.Value && prior.Layer == layer && prior.Field == field && prior.RuleID == ruleID {
				duplicate = true
				break
			}
		}
		if !duplicate && len(result.DimensionEvidence) < 48 {
			result.DimensionEvidence = append(result.DimensionEvidence, entry)
		}
	}
}

// mergeDimension never adds confidence for repeated library hits. A strong
// disagreement marks only this dimension; weak hints cannot replace confirmed
// values. The deterministic first winner is retained for evidence inspection.
func mergeDimension(result *Result, field, candidate string, confidence, conflictFloor float64) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || strings.Contains(candidate, "$") {
		return
	}
	var value *string
	var score *float64
	switch field {
	case "brand":
		value, score = &result.Brand, &result.BrandConfidence
	case "model":
		value, score = &result.Model, &result.ModelConfidence
	case "product_family":
		value, score = &result.ProductFamily, &result.ProductFamilyConfidence
	case "device_type":
		value, score = &result.DeviceType, &result.DeviceTypeConfidence
	case "os_family":
		value, score = &result.OSFamily, &result.OSFamilyConfidence
	default:
		return
	}
	if *value == "" || *score < conflictFloor && confidence > *score {
		// A narrower family may arrive after a high-confidence generic DHCP
		// label. Preserve its specificity even when the generic score is higher.
		if *value != "" && moreSpecificDimension(field, candidate, *value) {
			return
		}
		*value, *score = candidate, confidence
		return
	}
	if strings.EqualFold(*value, candidate) {
		*score = max(*score, confidence)
		return
	}
	if moreSpecificDimension(field, *value, candidate) {
		*value, *score = candidate, confidence
		return
	}
	if moreSpecificDimension(field, candidate, *value) {
		return
	}
	if *score >= conflictFloor && confidence >= conflictFloor {
		result.Conflict = true
		result.ConflictDimensions = appendConflictDimension(result.ConflictDimensions, field)
	}
}

func moreSpecificDimension(field, broad, specific string) bool {
	if field == "device_type" {
		return strings.EqualFold(broad, "mobile") && strings.EqualFold(specific, "tablet")
	}
	if field != "os_family" {
		return false
	}
	if strings.EqualFold(broad, "Apple OS") {
		return strings.EqualFold(specific, "iOS") || strings.EqualFold(specific, "iPadOS") || strings.EqualFold(specific, "macOS")
	}
	return strings.EqualFold(broad, "Android") && strings.EqualFold(specific, "HarmonyOS")
}

// Fingerbank interrogation is an additional DHCP interpretation. A different
// existing conclusion remains visible, with a conflict only when both sources
// are strong; a generic DHCP label must not erase a more specific rule.
func mergeFingerbankDimension(result *Result, field, candidate string, confidence float64) {
	if candidate == "" {
		return
	}
	var current string
	var currentConfidence float64
	switch field {
	case "device_type":
		current, currentConfidence = result.DeviceType, result.DeviceTypeConfidence
	case "os_family":
		current, currentConfidence = result.OSFamily, result.OSFamilyConfidence
	default:
		return
	}
	if current != "" && !strings.EqualFold(current, candidate) {
		if moreSpecificDimension(field, current, candidate) {
			mergeDimension(result, field, candidate, confidence, .85)
			return
		}
		if moreSpecificDimension(field, candidate, current) {
			return
		}
		if currentConfidence >= .85 && confidence >= .85 {
			result.Conflict = true
			result.ConflictDimensions = appendConflictDimension(result.ConflictDimensions, field)
		}
		return
	}
	mergeDimension(result, field, candidate, confidence, .85)
}

// Explicit family restrictions are an additional index within the field index.
// Unrestricted rules remain eligible to detect contradictory independent evidence.
func ruleAcceptsFamilies(families []string, candidates []ProductCandidate) bool {
	if len(families) == 0 {
		return true
	}
	for _, family := range families {
		for _, candidate := range candidates {
			if candidate.Family != "" && strings.EqualFold(strings.TrimSpace(family), candidate.Family) {
				return true
			}
		}
	}
	return false
}
