package srunapi

import "sort"

// This file turns observed endpoint shapes into a read-only contract verdict.
// It performs no network work and never treats an empty or partial response as
// authoritative absence. Callers use the verdict to decide whether an endpoint
// may serve as an authoritative online inventory.

// inventoryRequiredFields mirrors the online-inventory/v1 completeness contract
// in inventory_http.go and the identity requirements in legacy4k.IdentityRecords.
func inventoryRequiredFields() []string {
	return []string{"rad_online_id", "session_id", "user_name", "add_time"}
}

// inventoryAddressFields requires at least one usable address column.
func inventoryAddressFields() []string {
	return []string{"ip", "ipv6", "ip6"}
}

func inventoryOptionalFields() []string {
	return []string{"user_mac", "nas_ip", "group_id", "products_id", "device_id"}
}

// InventoryVerdict is the machine-readable judgement of whether the observed
// endpoints can prove a complete, fresh inventory.
type InventoryVerdict struct {
	Completeness          string   `json:"completeness"`
	CompleteEndpoints     []string `json:"complete_endpoints"`
	MissingRequiredFields []string `json:"missing_required_fields"`
	PresentOptionalFields []string `json:"present_optional_fields,omitempty"`
	EndpointBlockers      []string `json:"endpoint_blockers,omitempty"`
	Blockers              []string `json:"blockers"`
}

// BuildInventoryVerdict aggregates endpoint capabilities into one verdict.
//
// completeness is "proven" only when at least one endpoint reports Complete and
// every required field is observable across the observed endpoints. Newer,
// partial or empty responses never produce "proven"; they surface as blockers.
func BuildInventoryVerdict(caps []EquipmentCapabilities, required []string) InventoryVerdict {
	if len(required) == 0 {
		required = inventoryRequiredFields()
	}
	verdict := InventoryVerdict{
		Completeness:          "unproven",
		CompleteEndpoints:     []string{},
		MissingRequiredFields: []string{},
		Blockers:              []string{},
	}
	present := map[string]bool{}
	blockers := map[string]bool{}
	complete := 0
	for _, cap := range caps {
		if cap.Complete {
			complete++
		}
		if blocker := normalizeField(cap.Blocker); blocker != "" {
			blockers[blocker] = true
		}
		for _, field := range cap.Fields {
			present[normalizeField(field)] = true
		}
	}
	for _, field := range required {
		if !present[normalizeField(field)] {
			verdict.MissingRequiredFields = append(verdict.MissingRequiredFields, field)
		}
	}
	sort.Strings(verdict.MissingRequiredFields)

	addressPresent := false
	for _, field := range inventoryAddressFields() {
		if present[field] {
			addressPresent = true
		}
	}
	if !addressPresent {
		verdict.MissingRequiredFields = append(verdict.MissingRequiredFields, "ip|ipv6|ip6")
		sort.Strings(verdict.MissingRequiredFields)
	}

	for _, field := range inventoryOptionalFields() {
		if present[field] {
			verdict.PresentOptionalFields = append(verdict.PresentOptionalFields, field)
		}
	}
	sort.Strings(verdict.PresentOptionalFields)

	for _, blocker := range sortedKeys(blockers) {
		verdict.EndpointBlockers = append(verdict.EndpointBlockers, blocker)
	}

	// A native management endpoint deliberately reports Complete=false until the
	// source itself guarantees an atomic snapshot. An empty or partial response
	// is never upgraded to a proven authority.
	if complete == 0 {
		verdict.Blockers = append(verdict.Blockers, "inventory_completeness_unproven")
	}
	if !addressPresent {
		verdict.Blockers = append(verdict.Blockers, "inventory_address_field_missing")
	}
	if len(verdict.MissingRequiredFields) > 0 {
		verdict.Blockers = append(verdict.Blockers, "inventory_required_fields_missing:"+joinFields(verdict.MissingRequiredFields))
	}
	if len(caps) == 0 {
		verdict.Blockers = append(verdict.Blockers, "inventory_endpoint_unavailable")
	}
	if complete > 0 && len(verdict.MissingRequiredFields) == 0 {
		verdict.Completeness = "proven"
		verdict.Blockers = []string{}
	}
	return verdict
}

func normalizeField(value string) string {
	result := make([]rune, 0, len(value))
	for _, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
			result = append(result, r+('a'-'A'))
		case r != ' ':
			result = append(result, r)
		}
	}
	return string(result)
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func joinFields(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += ","
		}
		result += value
	}
	return result
}
