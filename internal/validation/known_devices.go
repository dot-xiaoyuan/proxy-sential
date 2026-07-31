package validation

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/store"
)

var knownDeviceRequiredHeaders = []string{
	"sample_id",
	"expected_endpoint_id",
	"primary_mac",
	"expected_account_id",
	"expected_owner_name",
	"expected_owner_department",
	"expected_device_type",
	"expected_os_family",
	"expected_vendor",
	"expected_ip",
	"expected_access_id",
	"expected_vlan",
	"expected_ap",
	"expected_switch_id",
	"expected_switch_port",
	"expected_role",
	"registration_status",
	"is_infrastructure",
	"is_nat_or_router",
	"expected_hidden_downstream_count",
	"first_seen",
	"last_seen",
	"notes",
}

var knownDeviceRoles = map[string]bool{
	"endpoint":       true,
	"gateway":        true,
	"infrastructure": true,
	"nat":            true,
	"network_device": true,
	"server":         true,
	"unknown":        true,
}

var knownDeviceRegistrationStatuses = map[string]bool{
	"registered":   true,
	"unregistered": true,
	"exempt":       true,
	"unknown":      true,
}

var infrastructureRoles = map[string]bool{
	"gateway":        true,
	"infrastructure": true,
	"nat":            true,
	"network_device": true,
	"server":         true,
}

type KnownDeviceSample struct {
	SampleID                      string `json:"sample_id"`
	ExpectedEndpointID            string `json:"expected_endpoint_id,omitempty"`
	PrimaryMAC                    string `json:"primary_mac,omitempty"`
	ExpectedAccountID             string `json:"expected_account_id,omitempty"`
	ExpectedOwnerName             string `json:"expected_owner_name,omitempty"`
	ExpectedOwnerDepartment       string `json:"expected_owner_department,omitempty"`
	ExpectedDeviceType            string `json:"expected_device_type,omitempty"`
	ExpectedOSFamily              string `json:"expected_os_family,omitempty"`
	ExpectedVendor                string `json:"expected_vendor,omitempty"`
	ExpectedIP                    string `json:"expected_ip,omitempty"`
	ExpectedAccessID              string `json:"expected_access_id,omitempty"`
	ExpectedVLAN                  string `json:"expected_vlan,omitempty"`
	ExpectedAP                    string `json:"expected_ap,omitempty"`
	ExpectedSwitchID              string `json:"expected_switch_id,omitempty"`
	ExpectedSwitchPort            string `json:"expected_switch_port,omitempty"`
	ExpectedRole                  string `json:"expected_role"`
	RegistrationStatus            string `json:"registration_status"`
	IsInfrastructure              bool   `json:"is_infrastructure"`
	IsNATOrRouter                 bool   `json:"is_nat_or_router"`
	ExpectedHiddenDownstreamCount int    `json:"expected_hidden_downstream_count"`
	FirstSeen                     string `json:"first_seen,omitempty"`
	LastSeen                      string `json:"last_seen,omitempty"`
	Notes                         string `json:"notes,omitempty"`
}

type KnownDeviceCoverage struct {
	Total             int            `json:"total"`
	Endpoints         int            `json:"endpoints"`
	Infrastructure    int            `json:"infrastructure"`
	NATOrRouters      int            `json:"nat_or_routers"`
	WirelessSamples   int            `json:"wireless_samples"`
	WiredSamples      int            `json:"wired_samples"`
	Registered        int            `json:"registered"`
	Unregistered      int            `json:"unregistered"`
	ByRole            map[string]int `json:"by_role"`
	ByDeviceType      map[string]int `json:"by_device_type"`
	ByOSFamily        map[string]int `json:"by_os_family"`
	ByAccessID        map[string]int `json:"by_access_id"`
	ByExpectedAccount map[string]int `json:"by_expected_account"`
}

type KnownDeviceValidationReport struct {
	Valid      bool                         `json:"valid"`
	Errors     []string                     `json:"errors"`
	Warnings   []string                     `json:"warnings"`
	Coverage   KnownDeviceCoverage          `json:"coverage"`
	Comparison *KnownDeviceComparisonReport `json:"comparison,omitempty"`
	Samples    []KnownDeviceSample          `json:"samples,omitempty"`
}

type KnownDeviceComparisonReport struct {
	Valid         bool                     `json:"valid"`
	Passed        int                      `json:"passed"`
	Failed        int                      `json:"failed"`
	EndpointTotal int                      `json:"endpoint_total"`
	InfraTotal    int                      `json:"infrastructure_total"`
	Results       []KnownDeviceMatchResult `json:"results"`
}

type KnownDeviceMatchResult struct {
	SampleID         string   `json:"sample_id"`
	ExpectedRole     string   `json:"expected_role"`
	Status           string   `json:"status"`
	MatchedEndpoint  string   `json:"matched_endpoint,omitempty"`
	MatchedInfra     string   `json:"matched_infrastructure,omitempty"`
	MatchedIPs       []string `json:"matched_ips,omitempty"`
	MatchedAccounts  []string `json:"matched_accounts,omitempty"`
	MatchedAccessIDs []string `json:"matched_access_ids,omitempty"`
	Issues           []string `json:"issues,omitempty"`
}

func AnalyzeKnownDeviceCSV(input io.Reader) (KnownDeviceValidationReport, error) {
	samples, errors, err := ParseKnownDeviceCSV(input)
	if err != nil {
		return KnownDeviceValidationReport{}, err
	}
	report := KnownDeviceValidationReport{
		Valid:    len(errors) == 0,
		Errors:   errors,
		Warnings: nil,
		Coverage: KnownDeviceCoverageFor(samples),
		Samples:  samples,
	}
	report.Warnings = KnownDeviceCoverageWarnings(report.Coverage)
	return report, nil
}

func AnalyzeKnownDeviceCSVWithIdentityState(input io.Reader, state store.IdentityState) (KnownDeviceValidationReport, error) {
	report, err := AnalyzeKnownDeviceCSV(input)
	if err != nil {
		return KnownDeviceValidationReport{}, err
	}
	comparison := CompareKnownDevicesToIdentityState(report.Samples, state)
	report.Comparison = &comparison
	report.Valid = report.Valid && comparison.Valid
	return report, nil
}

func CompareKnownDevicesToIdentityState(samples []KnownDeviceSample, state store.IdentityState) KnownDeviceComparisonReport {
	report := KnownDeviceComparisonReport{
		Valid:   true,
		Results: []KnownDeviceMatchResult{},
	}
	for _, sample := range samples {
		var result KnownDeviceMatchResult
		if sample.IsInfrastructure {
			report.InfraTotal++
			result = compareInfrastructureSample(sample, state)
		} else {
			report.EndpointTotal++
			result = compareEndpointSample(sample, state)
		}
		if len(result.Issues) > 0 {
			result.Status = "failed"
			report.Failed++
			report.Valid = false
		} else {
			result.Status = "passed"
			report.Passed++
		}
		report.Results = append(report.Results, result)
	}
	return report
}

func ParseKnownDeviceCSV(input io.Reader) ([]KnownDeviceSample, []string, error) {
	reader := csv.NewReader(input)
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("read known devices csv: %w", err)
	}
	if len(rows) == 0 {
		return nil, []string{"csv is empty"}, nil
	}

	headers := mapHeaders(rows[0])
	errors := validateKnownDeviceHeaders(headers)
	samples := make([]KnownDeviceSample, 0, len(rows)-1)
	seenSampleIDs := map[string]bool{}

	for rowIndex, row := range rows[1:] {
		line := rowIndex + 2
		if isBlankCSVRow(row) {
			continue
		}
		sample, rowErrors := parseKnownDeviceRow(line, row, headers)
		errors = append(errors, rowErrors...)
		if sample.SampleID != "" {
			if seenSampleIDs[sample.SampleID] {
				errors = append(errors, fmt.Sprintf("line %d: duplicate sample_id %q", line, sample.SampleID))
			}
			seenSampleIDs[sample.SampleID] = true
		}
		samples = append(samples, sample)
	}

	return samples, errors, nil
}

func KnownDeviceCoverageFor(samples []KnownDeviceSample) KnownDeviceCoverage {
	coverage := KnownDeviceCoverage{
		Total:             len(samples),
		ByRole:            map[string]int{},
		ByDeviceType:      map[string]int{},
		ByOSFamily:        map[string]int{},
		ByAccessID:        map[string]int{},
		ByExpectedAccount: map[string]int{},
	}
	for _, sample := range samples {
		role := normalizeLower(sample.ExpectedRole)
		coverage.ByRole[role]++
		if role == "endpoint" {
			coverage.Endpoints++
		}
		if sample.IsInfrastructure {
			coverage.Infrastructure++
		}
		if sample.IsNATOrRouter {
			coverage.NATOrRouters++
		}
		if sample.RegistrationStatus == "registered" {
			coverage.Registered++
		}
		if sample.RegistrationStatus == "unregistered" {
			coverage.Unregistered++
		}
		if sample.ExpectedAP != "" {
			coverage.WirelessSamples++
		}
		if sample.ExpectedSwitchID != "" || sample.ExpectedSwitchPort != "" {
			coverage.WiredSamples++
		}
		incrementIfSet(coverage.ByDeviceType, sample.ExpectedDeviceType)
		incrementIfSet(coverage.ByOSFamily, sample.ExpectedOSFamily)
		incrementIfSet(coverage.ByAccessID, sample.ExpectedAccessID)
		incrementIfSet(coverage.ByExpectedAccount, sample.ExpectedAccountID)
	}
	return coverage
}

func KnownDeviceCoverageWarnings(coverage KnownDeviceCoverage) []string {
	var warnings []string
	if coverage.Total < 30 {
		warnings = append(warnings, fmt.Sprintf("expected 30-50 known devices for acceptance, got %d", coverage.Total))
	}
	if coverage.Total > 50 {
		warnings = append(warnings, fmt.Sprintf("expected 30-50 known devices for acceptance, got %d", coverage.Total))
	}
	if coverage.Endpoints < 20 {
		warnings = append(warnings, fmt.Sprintf("expected at least 20 endpoint samples, got %d", coverage.Endpoints))
	}
	if coverage.Infrastructure < 5 {
		warnings = append(warnings, fmt.Sprintf("expected at least 5 infrastructure samples, got %d", coverage.Infrastructure))
	}
	if coverage.NATOrRouters < 1 {
		warnings = append(warnings, "expected at least 1 personal router/NAT sample")
	}
	if coverage.WirelessSamples < 5 {
		warnings = append(warnings, fmt.Sprintf("expected at least 5 wireless/AP samples, got %d", coverage.WirelessSamples))
	}
	if coverage.WiredSamples < 5 {
		warnings = append(warnings, fmt.Sprintf("expected at least 5 wired switch-port samples, got %d", coverage.WiredSamples))
	}
	if coverage.Registered < 5 || coverage.Unregistered < 5 {
		warnings = append(warnings, fmt.Sprintf("expected both registered and unregistered devices, got registered=%d unregistered=%d", coverage.Registered, coverage.Unregistered))
	}
	for _, deviceType := range []string{"windows_laptop", "phone", "tablet", "personal_router", "server"} {
		if coverage.ByDeviceType[deviceType] == 0 {
			warnings = append(warnings, fmt.Sprintf("missing expected device_type sample %q", deviceType))
		}
	}
	return warnings
}

func compareEndpointSample(sample KnownDeviceSample, state store.IdentityState) KnownDeviceMatchResult {
	result := KnownDeviceMatchResult{
		SampleID:     sample.SampleID,
		ExpectedRole: sample.ExpectedRole,
	}
	endpoint, ok := findEndpointForSample(sample, state)
	if !ok {
		result.Issues = append(result.Issues, "expected endpoint was not discovered")
		return result
	}
	result.MatchedEndpoint = endpoint.EndpointID
	profile, _ := store.BuildEndpointIdentityProfile(state, endpoint.EndpointID)
	result.MatchedIPs = uniqueStringsFromIPHistory(profile.IPHistory)
	result.MatchedAccounts = append([]string{}, profile.Accounts...)
	result.MatchedAccessIDs = uniqueStringsFromAccessHistory(profile.AccessHistory)

	if sample.ExpectedRole != "" && sample.ExpectedRole != "endpoint" && endpoint.EntityRole != sample.ExpectedRole {
		result.Issues = append(result.Issues, fmt.Sprintf("expected role %q, got %q", sample.ExpectedRole, endpoint.EntityRole))
	}
	if sample.PrimaryMAC != "" && endpoint.PrimaryMAC != "" && normalizeMAC(endpoint.PrimaryMAC) != sample.PrimaryMAC {
		result.Issues = append(result.Issues, fmt.Sprintf("expected primary_mac %q, got %q", sample.PrimaryMAC, endpoint.PrimaryMAC))
	}
	if sample.ExpectedAccountID != "" && !stringSliceContains(profile.Accounts, sample.ExpectedAccountID) && endpoint.OwnerAccount != sample.ExpectedAccountID {
		result.Issues = append(result.Issues, fmt.Sprintf("expected account %q was not linked", sample.ExpectedAccountID))
	}
	if sample.ExpectedIP != "" && !ipHistoryContains(profile.IPHistory, sample.ExpectedIP) {
		result.Issues = append(result.Issues, fmt.Sprintf("expected ip %q was not linked", sample.ExpectedIP))
	}
	if sample.ExpectedAccessID != "" && !accessHistoryContains(profile.AccessHistory, func(item store.IdentityAccessHistory) bool {
		return item.AccessID == sample.ExpectedAccessID
	}) {
		result.Issues = append(result.Issues, fmt.Sprintf("expected access_id %q was not linked", sample.ExpectedAccessID))
	}
	if sample.ExpectedAP != "" && !accessHistoryContains(profile.AccessHistory, func(item store.IdentityAccessHistory) bool {
		return item.AP == sample.ExpectedAP
	}) {
		result.Issues = append(result.Issues, fmt.Sprintf("expected ap %q was not linked", sample.ExpectedAP))
	}
	if sample.ExpectedSwitchID != "" && !accessHistoryContains(profile.AccessHistory, func(item store.IdentityAccessHistory) bool {
		return item.SwitchID == sample.ExpectedSwitchID
	}) {
		result.Issues = append(result.Issues, fmt.Sprintf("expected switch_id %q was not linked", sample.ExpectedSwitchID))
	}
	if sample.ExpectedSwitchPort != "" && !accessHistoryContains(profile.AccessHistory, func(item store.IdentityAccessHistory) bool {
		return item.SwitchPort == sample.ExpectedSwitchPort
	}) {
		result.Issues = append(result.Issues, fmt.Sprintf("expected switch_port %q was not linked", sample.ExpectedSwitchPort))
	}
	if sample.ExpectedVLAN != "" && !accessHistoryContains(profile.AccessHistory, func(item store.IdentityAccessHistory) bool {
		return item.VLAN == sample.ExpectedVLAN
	}) {
		result.Issues = append(result.Issues, fmt.Sprintf("expected vlan %q was not linked", sample.ExpectedVLAN))
	}
	return result
}

func compareInfrastructureSample(sample KnownDeviceSample, state store.IdentityState) KnownDeviceMatchResult {
	result := KnownDeviceMatchResult{
		SampleID:     sample.SampleID,
		ExpectedRole: sample.ExpectedRole,
	}
	entity, ok := findInfrastructureForSample(sample, state)
	if !ok {
		result.Issues = append(result.Issues, "expected infrastructure entity was not discovered")
		return result
	}
	result.MatchedInfra = entity.EntityID
	if sample.ExpectedRole != "" && entity.EntityRole != sample.ExpectedRole {
		result.Issues = append(result.Issues, fmt.Sprintf("expected role %q, got %q", sample.ExpectedRole, entity.EntityRole))
	}
	if sample.ExpectedIP != "" && entity.IP != sample.ExpectedIP {
		result.Issues = append(result.Issues, fmt.Sprintf("expected infrastructure ip %q, got %q", sample.ExpectedIP, entity.IP))
	}
	if sample.PrimaryMAC != "" && normalizeMAC(entity.MAC) != sample.PrimaryMAC {
		result.Issues = append(result.Issues, fmt.Sprintf("expected infrastructure mac %q, got %q", sample.PrimaryMAC, entity.MAC))
	}
	if endpointHasSampleIPOrMAC(sample, state) {
		result.Issues = append(result.Issues, "infrastructure identifier also appears as endpoint")
	}
	return result
}

func validateKnownDeviceHeaders(headers map[string]int) []string {
	var errors []string
	for _, header := range knownDeviceRequiredHeaders {
		if _, ok := headers[header]; !ok {
			errors = append(errors, fmt.Sprintf("missing required header %q", header))
		}
	}
	return errors
}

func parseKnownDeviceRow(line int, row []string, headers map[string]int) (KnownDeviceSample, []string) {
	value := func(header string) string {
		index, ok := headers[header]
		if !ok || index >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[index])
	}

	var errors []string
	parseBoolField := func(header string) bool {
		parsed, err := parseKnownDeviceBool(value(header))
		if err != nil {
			errors = append(errors, fmt.Sprintf("line %d: %s", line, err.Error()))
		}
		return parsed
	}
	parseIntField := func(header string) int {
		raw := value(header)
		if raw == "" {
			return 0
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			errors = append(errors, fmt.Sprintf("line %d: %s must be a non-negative integer", line, header))
			return 0
		}
		return parsed
	}

	sample := KnownDeviceSample{
		SampleID:                      value("sample_id"),
		ExpectedEndpointID:            value("expected_endpoint_id"),
		PrimaryMAC:                    normalizeMAC(value("primary_mac")),
		ExpectedAccountID:             value("expected_account_id"),
		ExpectedOwnerName:             value("expected_owner_name"),
		ExpectedOwnerDepartment:       value("expected_owner_department"),
		ExpectedDeviceType:            normalizeLower(value("expected_device_type")),
		ExpectedOSFamily:              normalizeLower(value("expected_os_family")),
		ExpectedVendor:                value("expected_vendor"),
		ExpectedIP:                    value("expected_ip"),
		ExpectedAccessID:              value("expected_access_id"),
		ExpectedVLAN:                  value("expected_vlan"),
		ExpectedAP:                    value("expected_ap"),
		ExpectedSwitchID:              value("expected_switch_id"),
		ExpectedSwitchPort:            value("expected_switch_port"),
		ExpectedRole:                  normalizeLower(value("expected_role")),
		RegistrationStatus:            normalizeLower(value("registration_status")),
		IsInfrastructure:              parseBoolField("is_infrastructure"),
		IsNATOrRouter:                 parseBoolField("is_nat_or_router"),
		ExpectedHiddenDownstreamCount: parseIntField("expected_hidden_downstream_count"),
		FirstSeen:                     value("first_seen"),
		LastSeen:                      value("last_seen"),
		Notes:                         value("notes"),
	}

	errors = append(errors, validateKnownDeviceSample(line, sample)...)
	return sample, errors
}

func validateKnownDeviceSample(line int, sample KnownDeviceSample) []string {
	var errors []string
	if sample.SampleID == "" {
		errors = append(errors, fmt.Sprintf("line %d: sample_id is required", line))
	}
	if !knownDeviceRoles[sample.ExpectedRole] {
		errors = append(errors, fmt.Sprintf("line %d: expected_role must be one of %s", line, sortedKeys(knownDeviceRoles)))
	}
	if !knownDeviceRegistrationStatuses[sample.RegistrationStatus] {
		errors = append(errors, fmt.Sprintf("line %d: registration_status must be one of %s", line, sortedKeys(knownDeviceRegistrationStatuses)))
	}
	if sample.PrimaryMAC != "" {
		if _, err := net.ParseMAC(sample.PrimaryMAC); err != nil {
			errors = append(errors, fmt.Sprintf("line %d: primary_mac is invalid", line))
		}
	}
	if sample.ExpectedIP != "" && net.ParseIP(sample.ExpectedIP) == nil {
		errors = append(errors, fmt.Sprintf("line %d: expected_ip is invalid", line))
	}
	if sample.ExpectedRole == "endpoint" && sample.PrimaryMAC == "" && sample.ExpectedEndpointID == "" {
		errors = append(errors, fmt.Sprintf("line %d: endpoint sample requires primary_mac or expected_endpoint_id", line))
	}
	if sample.IsInfrastructure && !infrastructureRoles[sample.ExpectedRole] {
		errors = append(errors, fmt.Sprintf("line %d: is_infrastructure=true requires an infrastructure role", line))
	}
	if !sample.IsInfrastructure && infrastructureRoles[sample.ExpectedRole] {
		errors = append(errors, fmt.Sprintf("line %d: infrastructure role requires is_infrastructure=true", line))
	}
	if sample.IsInfrastructure && sample.ExpectedAccountID != "" {
		errors = append(errors, fmt.Sprintf("line %d: infrastructure sample should not have expected_account_id", line))
	}
	if sample.ExpectedHiddenDownstreamCount > 0 && !sample.IsNATOrRouter {
		errors = append(errors, fmt.Sprintf("line %d: hidden downstream count requires is_nat_or_router=true", line))
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "first_seen", value: sample.FirstSeen},
		{name: "last_seen", value: sample.LastSeen},
	} {
		if field.value == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, field.value); err != nil {
			errors = append(errors, fmt.Sprintf("line %d: %s must be RFC3339", line, field.name))
		}
	}
	return errors
}

func mapHeaders(row []string) map[string]int {
	headers := map[string]int{}
	for index, header := range row {
		headers[strings.TrimSpace(header)] = index
	}
	return headers
}

func isBlankCSVRow(row []string) bool {
	for _, cell := range row {
		if strings.TrimSpace(cell) != "" {
			return false
		}
	}
	return true
}

func parseKnownDeviceBool(raw string) (bool, error) {
	normalized := normalizeLower(raw)
	switch normalized {
	case "true", "1", "yes", "y":
		return true, nil
	case "false", "0", "no", "n", "":
		return false, nil
	default:
		return false, fmt.Errorf("%q must be boolean", raw)
	}
}

func findEndpointForSample(sample KnownDeviceSample, state store.IdentityState) (store.EndpointEntity, bool) {
	candidates := []string{}
	if sample.ExpectedEndpointID != "" {
		candidates = append(candidates, sample.ExpectedEndpointID)
	}
	if sample.PrimaryMAC != "" {
		candidates = append(candidates, "mac:"+sample.PrimaryMAC)
	}
	for _, endpoint := range state.Endpoints {
		for _, candidate := range candidates {
			if endpoint.EndpointID == candidate {
				return endpoint, true
			}
		}
		if sample.PrimaryMAC != "" && normalizeMAC(endpoint.PrimaryMAC) == sample.PrimaryMAC {
			return endpoint, true
		}
	}
	return store.EndpointEntity{}, false
}

func findInfrastructureForSample(sample KnownDeviceSample, state store.IdentityState) (store.InfrastructureEntity, bool) {
	for _, entity := range state.Infrastructure {
		if sample.ExpectedEndpointID != "" && entity.EntityID == sample.ExpectedEndpointID {
			return entity, true
		}
		if sample.ExpectedIP != "" && entity.IP == sample.ExpectedIP {
			return entity, true
		}
		if sample.PrimaryMAC != "" && normalizeMAC(entity.MAC) == sample.PrimaryMAC {
			return entity, true
		}
	}
	return store.InfrastructureEntity{}, false
}

func endpointHasSampleIPOrMAC(sample KnownDeviceSample, state store.IdentityState) bool {
	for _, endpoint := range state.Endpoints {
		if sample.PrimaryMAC != "" && normalizeMAC(endpoint.PrimaryMAC) == sample.PrimaryMAC {
			return true
		}
	}
	if sample.ExpectedIP == "" && sample.PrimaryMAC == "" {
		return false
	}
	for _, item := range state.IPMACHistory {
		if sample.ExpectedIP != "" && item.IP == sample.ExpectedIP && item.EntityRole == "endpoint" {
			return true
		}
		if sample.PrimaryMAC != "" && normalizeMAC(item.MAC) == sample.PrimaryMAC && item.EntityRole == "endpoint" {
			return true
		}
	}
	return false
}

func ipHistoryContains(history []store.IdentityIPMACHistory, ip string) bool {
	for _, item := range history {
		if item.IP == ip {
			return true
		}
	}
	return false
}

func accessHistoryContains(history []store.IdentityAccessHistory, matches func(store.IdentityAccessHistory) bool) bool {
	for _, item := range history {
		if matches(item) {
			return true
		}
	}
	return false
}

func uniqueStringsFromIPHistory(history []store.IdentityIPMACHistory) []string {
	values := make([]string, 0, len(history))
	seen := map[string]bool{}
	for _, item := range history {
		if item.IP == "" || seen[item.IP] {
			continue
		}
		seen[item.IP] = true
		values = append(values, item.IP)
	}
	sort.Strings(values)
	return values
}

func uniqueStringsFromAccessHistory(history []store.IdentityAccessHistory) []string {
	values := make([]string, 0, len(history))
	seen := map[string]bool{}
	for _, item := range history {
		if item.AccessID == "" || seen[item.AccessID] {
			continue
		}
		seen[item.AccessID] = true
		values = append(values, item.AccessID)
	}
	sort.Strings(values)
	return values
}

func stringSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func normalizeMAC(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "-", ":")
	return value
}

func normalizeLower(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func incrementIfSet(values map[string]int, value string) {
	value = normalizeLower(value)
	if value == "" {
		return
	}
	values[value]++
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
