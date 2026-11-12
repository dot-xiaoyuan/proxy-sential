package fingerprint

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	recog "github.com/runZeroInc/recog-go"
)

// HardwareInput contains already attributed evidence for ONE scoped identity.
// The caller owns scope separation, revocation and address lease validation.
// Service TTL is deliberately not the lifetime of a hardware identity fact.
type HardwareInput struct {
	Evidence        []EvidenceSignal
	IdentityTrusted bool
}
type HardwareSource struct {
	Source       string            `json:"source"`
	RuleID       string            `json:"rule_id"`
	RuleVersion  string            `json:"rule_version"`
	EvidenceID   string            `json:"evidence_id"`
	SourceFamily string            `json:"source_family,omitempty"`
	ObservedAt   time.Time         `json:"observed_at"`
	Fields       map[string]string `json:"fields,omitempty"`
}
type HardwareSourceReport struct {
	Source         string `json:"source"`
	Imported       int    `json:"imported"`
	Executable     int    `json:"executable"`
	InputAvailable int    `json:"input_available"`
	Matched        int    `json:"matched"`
	FormedType     int    `json:"formed_type"`
}
type HardwareUnsupported struct {
	Source string `json:"source"`
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
}
type HardwareResult struct {
	SourceStatus      string                 `json:"source_status"`
	BundleVersion     string                 `json:"bundle_version,omitempty"`
	BundleSchema      string                 `json:"bundle_schema,omitempty"`
	Incomplete        bool                   `json:"incomplete,omitempty"`
	Error             string                 `json:"error,omitempty"`
	RejectedSignals   int                    `json:"rejected_signals,omitempty"`
	RejectedReasons   map[string]int         `json:"rejected_reasons,omitempty"`
	Type              string                 `json:"type,omitempty"`
	Model             string                 `json:"model,omitempty"`
	Manufacturer      string                 `json:"manufacturer,omitempty"`
	TypeStatus        string                 `json:"type_status,omitempty"`
	ModelStatus       string                 `json:"model_status,omitempty"`
	Version           string                 `json:"version"`
	Sources           []HardwareSource       `json:"sources,omitempty"`
	Capabilities      []string               `json:"capabilities,omitempty"`
	ConflictingTypes  []string               `json:"conflicting_types,omitempty"`
	ConflictingModels []string               `json:"conflicting_models,omitempty"`
	SourceReports     []HardwareSourceReport `json:"source_reports"`
}
type HardwareCondition struct {
	All      []HardwareCondition `json:"all,omitempty"`
	Any      []HardwareCondition `json:"any,omitempty"`
	Not      *HardwareCondition  `json:"not,omitempty"`
	Field    string              `json:"field,omitempty"`
	Operator string              `json:"operator,omitempty"`
	Value    string              `json:"value,omitempty"`
	re       *regexp.Regexp
}
type HardwareSNMPRule struct {
	ID           string              `json:"id"`
	Source       string              `json:"source"`
	Version      string              `json:"version"`
	Name         string              `json:"name"`
	Type         string              `json:"type"`
	Condition    HardwareCondition   `json:"condition"`
	ModelOID     string              `json:"model_oid,omitempty"`
	ModelPattern string              `json:"model_pattern,omitempty"`
	RawRef       string              `json:"raw_ref"`
	RawSHA256    string              `json:"raw_sha256"`
	Extractors   []HardwareExtractor `json:"extractors,omitempty"`
}
type HardwareExtractor struct {
	Field            string `json:"field"`
	Pattern          string `json:"pattern,omitempty"`
	Capture          string `json:"capture,omitempty"`
	RawRef           string `json:"raw_ref"`
	RawSHA256        string `json:"raw_sha256"`
	ResolutionRef    string `json:"resolution_ref,omitempty"`
	ResolutionSHA256 string `json:"resolution_sha256,omitempty"`
	compiled         *regexp.Regexp
}
type hardwareModelRule struct {
	ID           string   `json:"id"`
	Source       string   `json:"source"`
	Version      string   `json:"version"`
	Pattern      string   `json:"pattern"`
	Type         string   `json:"type"`
	Model        string   `json:"model"`
	Manufacturer string   `json:"manufacturer"`
	RawRef       string   `json:"raw_ref"`
	RawSHA256    string   `json:"raw_sha256"`
	Rationale    string   `json:"rationale"`
	Positive     []string `json:"positive"`
	Negative     []string `json:"negative"`
	SourceURL    string   `json:"source_url,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	compiled     *regexp.Regexp
}
type nativeHardwareRule struct {
	field, id, version string
	fp                 *recog.Fingerprint
}
type HardwareCatalog struct {
	Version     string
	Sources     []BundleSource
	Unsupported []HardwareUnsupported
	models      []hardwareModelRule
	snmp        []HardwareSNMPRule
	native      []nativeHardwareRule
	reports     map[string]HardwareSourceReport
}
type hardwareCatalogDocument struct {
	Version          string                `json:"version"`
	ConverterVersion string                `json:"converter_version"`
	Sources          []BundleSource        `json:"sources"`
	Models           []hardwareModelRule   `json:"models"`
	SNMP             []HardwareSNMPRule    `json:"snmp"`
	RecogFiles       map[string]string     `json:"recog_files"`
	Unsupported      []HardwareUnsupported `json:"unsupported"`
	SourceCounts     map[string]int        `json:"source_counts,omitempty"`
}

//go:embed data/hardware-catalog.json
var embeddedHardwareCatalog []byte

//go:embed data/hardware-provenance.json
var embeddedHardwareProvenance []byte
var hardwareOnce sync.Once
var embeddedHardware *HardwareCatalog

func defaultHardwareCatalog() *HardwareCatalog {
	hardwareOnce.Do(func() {
		var err error
		embeddedHardware, err = ParseHardwareCatalog(embeddedHardwareCatalog, embeddedProvenance, embeddedHardwareProvenance)
		if err != nil {
			panic(err)
		}
	})
	return embeddedHardware
}

// EvaluateHardware is the 204 hardware adjudication entry point. Legacy
// IdentifyEvidence remains unchanged for V7/184 consumers.
func EvaluateHardware(input HardwareInput, now time.Time) HardwareResult {
	return Default().EvaluateHardware(input, now)
}
func (l *Library) EvaluateHardware(input HardwareInput, now time.Time) HardwareResult {
	if l.installedBundleSchema != "" && (l.installedBundleSchema != BundleSchemaVersionV8 || l.hardware == nil) {
		return HardwareResult{SourceStatus: "unavailable", BundleVersion: l.version, BundleSchema: l.installedBundleSchema, Incomplete: true, Error: "installed fingerprint bundle has no verified V8 hardware catalog"}
	}
	h := l.hardware
	source := "explicit_replay"
	if h == nil {
		h = defaultHardwareCatalog()
		source = "embedded_replay"
	}
	result := h.Evaluate(input, now)
	result.SourceStatus = source
	if l.installedBundleSchema == BundleSchemaVersionV8 {
		result.SourceStatus = "verified_bundle"
		result.BundleSchema = l.installedBundleSchema
		result.BundleVersion = l.version
	}
	return result
}
func (l *Library) LoadHardwareCatalog(data, provenance []byte, extra ...[]byte) error {
	h, err := ParseHardwareCatalog(data, provenance, extra...)
	if err == nil {
		l.hardware = h
	}
	return err
}

func ParseHardwareCatalog(data, provenance []byte, extra ...[]byte) (*HardwareCatalog, error) {
	var d hardwareCatalogDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	if d.Version == "" || d.ConverterVersion == "" {
		return nil, fmt.Errorf("hardware catalog lacks version")
	}
	var raw map[string]string
	if err := json.Unmarshal(provenance, &raw); err != nil {
		return nil, err
	}
	for _, bytes := range extra {
		var additional map[string]string
		if err := json.Unmarshal(bytes, &additional); err != nil {
			return nil, err
		}
		for k, v := range additional {
			if prev, exists := raw[k]; exists && prev != v {
				return nil, fmt.Errorf("hardware provenance overwrites %s", k)
			}
			raw[k] = v
		}
	}
	verifyRaw := func(ref, hash string) error {
		if ref == "" {
			return nil
		}
		value, ok := raw[ref]
		if !ok {
			return fmt.Errorf("hardware raw reference missing: %s", ref)
		}
		sum := sha256.Sum256([]byte(value))
		if hex.EncodeToString(sum[:]) != hash {
			return fmt.Errorf("hardware raw hash mismatch: %s", ref)
		}
		return nil
	}
	h := &HardwareCatalog{Version: d.Version, Sources: d.Sources, Unsupported: d.Unsupported, reports: map[string]HardwareSourceReport{}}
	add := func(source string, executable bool) {
		r := h.reports[source]
		r.Source = source
		r.Imported++
		if executable {
			r.Executable++
		}
		h.reports[source] = r
	}
	for _, r := range d.Models {
		if r.RawRef == "" || r.Rationale == "" || len(r.Positive) == 0 || len(r.Negative) == 0 {
			return nil, fmt.Errorf("model %s lacks reviewed provenance or replay cases", r.ID)
		}
		if err := verifyRaw(r.RawRef, r.RawSHA256); err != nil {
			return nil, err
		}
		add(r.Source, true)
		var err error
		r.compiled, err = regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("model %s: %w", r.ID, err)
		}
		for _, v := range r.Positive {
			if !r.compiled.MatchString(v) {
				return nil, fmt.Errorf("model %s positive fixture fails: %s", r.ID, v)
			}
		}
		for _, v := range r.Negative {
			if r.compiled.MatchString(v) {
				return nil, fmt.Errorf("model %s negative fixture matches: %s", r.ID, v)
			}
		}
		h.models = append(h.models, r)
	}
	for _, r := range d.SNMP {
		if err := verifyRaw(r.RawRef, r.RawSHA256); err != nil {
			return nil, err
		}
		if err := r.Condition.compile(0); err != nil {
			h.Unsupported = append(h.Unsupported, HardwareUnsupported{r.Source, r.ID, err.Error()})
			add(r.Source, false)
			continue
		}
		add(r.Source, true)
		for i := range r.Extractors {
			ex := &r.Extractors[i]
			if err := verifyRaw(ex.RawRef, ex.RawSHA256); err != nil {
				return nil, err
			}
			if err := verifyRaw(ex.ResolutionRef, ex.ResolutionSHA256); err != nil {
				return nil, err
			}
			if ex.Pattern != "" {
				var err error
				ex.compiled, err = regexp.Compile(ex.Pattern)
				if err != nil {
					return nil, fmt.Errorf("hardware extractor %s: %w", r.ID, err)
				}
			}
		}
		if len(r.Extractors) > 0 {
			add("librenms_hardware", true)
		}
		h.snmp = append(h.snmp, r)
	}
	for _, u := range d.Unsupported {
		add(u.Source, false)
	}
	version := ""
	for _, s := range d.Sources {
		if s.Name == "recog" {
			version = s.Version
		}
	}
	paths := make([]string, 0, len(d.RecogFiles))
	for path := range d.RecogFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		value, ok := raw[path]
		if !ok {
			return nil, fmt.Errorf("native Recog XML missing: %s", path)
		}
		var db recog.FingerprintDB
		if err := xml.Unmarshal([]byte(value), &db); err != nil {
			return nil, fmt.Errorf("Recog %s: %w", path, err)
		}
		for i, fp := range db.Fingerprints {
			id := fmt.Sprintf("%s:%d", path, i)
			reason := ""
			field := d.RecogFiles[path]
			if field == "" {
				reason = "standard-event input unavailable"
			} else if err := fp.Normalize(); err != nil {
				reason = err.Error()
			} else if nativeExternalExample(fp) {
				reason = "external example file is unsupported; no filesystem reads allowed"
			} else if err := fp.VerifyExamples(""); err != nil {
				reason = "native example validation: " + err.Error()
			}
			add("recog", reason == "")
			if reason != "" {
				h.Unsupported = append(h.Unsupported, HardwareUnsupported{"recog", id, reason})
				continue
			}
			h.native = append(h.native, nativeHardwareRule{field, id, version, fp})
		}
	}
	for source, count := range d.SourceCounts {
		r := h.reports[source]
		if count < r.Executable {
			return nil, fmt.Errorf("invalid source count for %s", source)
		}
		r.Imported = count
		h.reports[source] = r
	}
	return h, nil
}

func nativeExternalExample(fp *recog.Fingerprint) bool {
	for _, ex := range fp.Examples {
		for _, a := range ex.Values {
			if a.Name.Local == "_filename" {
				return true
			}
		}
	}
	return false
}

func (c *HardwareCondition) compile(depth int) error {
	if depth > 12 {
		return fmt.Errorf("condition nesting limit")
	}
	modes := 0
	if len(c.All) > 0 {
		modes++
	}
	if len(c.Any) > 0 {
		modes++
	}
	if c.Not != nil {
		modes++
	}
	if c.Field != "" {
		modes++
	}
	if modes != 1 {
		return fmt.Errorf("ambiguous/empty condition")
	}
	for i := range c.All {
		if err := c.All[i].compile(depth + 1); err != nil {
			return err
		}
	}
	for i := range c.Any {
		if err := c.Any[i].compile(depth + 1); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return c.Not.compile(depth + 1)
	}
	if c.Field != "" {
		switch c.Operator {
		case "exact", "contains", "oid_prefix":
		case "regex":
			var err error
			c.re, err = regexp.Compile(c.Value)
			if err != nil {
				return fmt.Errorf("unsupported regex: %w", err)
			}
		default:
			return fmt.Errorf("unsupported operator %s", c.Operator)
		}
	}
	return nil
}

// The second boolean is completeness. NOT(missing) is missing, never true.
func (c HardwareCondition) match(values map[string][]string) (bool, bool) {
	if len(c.All) > 0 {
		for _, a := range c.All {
			m, available := a.match(values)
			if !available {
				return false, false
			}
			if !m {
				return false, true
			}
		}
		return true, true
	}
	if len(c.Any) > 0 {
		available := true
		for _, a := range c.Any {
			m, ok := a.match(values)
			if m && ok {
				return true, true
			}
			available = available && ok
		}
		return false, available
	}
	if c.Not != nil {
		m, ok := c.Not.match(values)
		return !m && ok, ok
	}
	v, ok := values[c.Field]
	if !ok || len(v) == 0 {
		return false, false
	}
	for _, value := range v {
		matched := false
		switch c.Operator {
		case "exact":
			matched = value == c.Value
		case "contains":
			matched = strings.Contains(value, c.Value)
		case "oid_prefix":
			x := strings.Trim(value, ".")
			p := strings.Trim(c.Value, ".")
			matched = x == p || strings.HasPrefix(x, p+".")
		case "regex":
			r := c.re
			if r == nil {
				r, _ = regexp.Compile(c.Value)
			}
			matched = r != nil && r.MatchString(value)
		}
		if matched {
			return true, true
		}
	}
	return false, true
}

func CanonicalHardwareType(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	v = strings.ReplaceAll(v, " ", "_")
	switch v {
	case "nvr", "dvr":
		return "recorder"
	case "environment", "environment_sensor", "environmental_monitor":
		return "environment_monitor"
	case "ip_camera", "web_cam", "ip_network_camera":
		return "camera"
	case "wap", "wireless_access_point":
		return "access_point"
	case "multifunction_device":
		return "printer"
	case "voip", "voip_phone":
		return "voip_phone"
	case "attendance":
		return "access_control"
	case "power_distribution_unit":
		return "pdu"
	case "uninterruptible_power_supply":
		return "ups"
	}
	switch v {
	case "printer", "scanner", "camera", "recorder", "access_control", "router", "switch", "access_point", "firewall", "ups", "pdu", "environment_monitor", "desktop", "laptop", "mobile", "tablet", "nas", "storage", "media_player", "media_device", "display", "tv", "network_adapter", "wireless_controller":
		return v
	}
	return ""
}

func hardwareEvidenceAccepted(s EvidenceSignal, now time.Time) bool {
	if s.EventID == "" || s.ObservedAt.IsZero() || s.ObservedAt.After(now) || len(s.Value) > 65536 {
		return false
	}
	if s.Association != "direct" && s.Association != "mac" && s.Association != "unique_lease" && s.Association != "unique_stream_binding" {
		return false
	}
	if s.Protocol == "sadp" {
		return s.Field == "sadp_model" && s.Direction == "device" && len(s.Value) <= 512
	}
	if s.Field == "snmp_oid_values" {
		return s.Protocol == "snmp" && s.Direction == "device"
	}
	want, ok := physicalEvidenceFields[s.Field]
	return ok && s.Direction == want && evidenceProtocolAllowsField(s.Protocol, s.Field) && len(s.Value) <= 16384
}

func hardwareRejectedReason(s EvidenceSignal, now time.Time) string {
	if s.EventID == "" || s.ObservedAt.IsZero() {
		return "missing_reference_or_observation_time"
	}
	if s.ObservedAt.After(now) {
		return "future_observation"
	}
	if s.Association != "direct" && s.Association != "mac" && s.Association != "unique_lease" && s.Association != "unique_stream_binding" {
		return "untrusted_association"
	}
	if s.Protocol == "sadp" {
		if s.Field != "sadp_model" {
			return "unsupported_protocol_field"
		}
		return "wrong_direction"
	}
	want, ok := physicalEvidenceFields[s.Field]
	if s.Field == "snmp_oid_values" {
		want = "device"
		ok = s.Protocol == "snmp"
	}
	if !ok || !evidenceProtocolAllowsField(s.Protocol, s.Field) {
		return "unsupported_protocol_field"
	}
	if want != s.Direction {
		return "wrong_direction"
	}
	return "field_limit"
}

func (h *HardwareCatalog) Evaluate(input HardwareInput, now time.Time) HardwareResult {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := HardwareResult{Version: h.Version, SourceStatus: "explicit_replay"}
	reports := map[string]HardwareSourceReport{}
	for k, v := range h.reports {
		reports[k] = v
	}
	deferReports := func() {
		keys := make([]string, 0, len(reports))
		for k := range reports {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out.SourceReports = append(out.SourceReports, reports[k])
		}
	}
	if !input.IdentityTrusted {
		deferReports()
		return out
	}
	evidence := append([]EvidenceSignal(nil), input.Evidence...)
	sort.Slice(evidence, func(i, j int) bool {
		a, b := evidence[i], evidence[j]
		return a.EventID+"\x00"+a.Field+"\x00"+a.Value < b.EventID+"\x00"+b.Field+"\x00"+b.Value
	})
	if len(evidence) > 128 {
		out.Incomplete = true
		out.Error = "hardware evidence exceeds 128 signals"
		deferReports()
		return out
	}
	types, models, brands, caps := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	seen := map[string]bool{}
	seenInputs := map[string]bool{}
	groups := map[string]map[string][]string{}
	groupRefs := map[string]EvidenceSignal{}
	record := func(source, id, version, kind, model, brand string, s EvidenceSignal, fields map[string]string) {
		key := source + "\x00" + id + "\x00" + s.SourceFamily + "\x00" + s.Protocol + "\x00" + s.EventID
		if seen[key] {
			return
		}
		seen[key] = true
		if len(model) > 512 || len(brand) > 256 {
			out.Incomplete = true
			out.Error = "hardware capture exceeds result field limit"
			return
		}
		if len(out.Sources) >= 512 {
			out.Incomplete = true
			out.Error = "hardware matches exceed 512 source results"
			return
		}
		r := reports[source]
		r.Source = source
		r.Matched++
		kind = CanonicalHardwareType(kind)
		if kind != "" {
			types[kind] = true
			r.FormedType++
		}
		reports[source] = r
		if model != "" {
			models[model] = true
		}
		if brand != "" {
			brands[brand] = true
		}
		if kind == "printer" && strings.EqualFold(fields["hw.device"], "Multifunction Device") {
			caps["scanning"] = true
		}
		out.Sources = append(out.Sources, HardwareSource{Source: source, RuleID: id, RuleVersion: version, EvidenceID: s.EventID, SourceFamily: s.SourceFamily, ObservedAt: s.ObservedAt, Fields: fields})
	}
	for _, s := range evidence {
		if len(s.Value) > 65536 || (s.Field != "snmp_oid_values" && len(s.Value) > 16384) || (hardwareModelField(s.Field) && len(s.Value) > 512) {
			out.Incomplete = true
			out.Error = "hardware evidence value exceeds field limit"
			out.RejectedSignals++
			if out.RejectedReasons == nil {
				out.RejectedReasons = map[string]int{}
			}
			out.RejectedReasons["field_limit"]++
			continue
		}
		if !hardwareEvidenceAccepted(s, now) {
			out.RejectedSignals++
			if out.RejectedReasons == nil {
				out.RejectedReasons = map[string]int{}
			}
			out.RejectedReasons[hardwareRejectedReason(s, now)]++
			continue
		}
		inputKey := s.SourceFamily + "\x00" + s.Protocol + "\x00" + s.EventID + "\x00" + s.Field + "\x00" + s.Value
		if seenInputs[inputKey] {
			continue
		}
		seenInputs[inputKey] = true
		key := s.SourceFamily + "\x00" + s.Protocol + "\x00" + s.EventID
		if groups[key] == nil {
			groups[key] = map[string][]string{}
			groupRefs[key] = s
		}
		groups[key][s.Field] = append(groups[key][s.Field], s.Value)
		if s.Field == "snmp_oid_values" {
			var oids map[string]string
			if json.Unmarshal([]byte(s.Value), &oids) == nil && len(oids) <= 128 {
				for oid, v := range oids {
					if len(v) <= 2048 {
						groups[key]["oid:"+strings.Trim(oid, ".")] = []string{v}
					} else {
						out.Incomplete = true
						out.Error = "SNMP varbind value exceeds limit"
					}
				}
			} else {
				out.Incomplete = true
				out.Error = "invalid or excessive SNMP varbind map"
			}
		}
		if hardwareModelField(s.Field) {
			for _, r := range h.models {
				report := reports[r.Source]
				report.InputAvailable++
				reports[r.Source] = report
				if r.compiled.MatchString(s.Value) {
					model := r.Model
					if model == "" {
						model = r.compiled.FindString(s.Value)
					}
					record(r.Source, r.ID, r.Version, r.Type, model, r.Manufacturer, s, nil)
					for _, c := range r.Capabilities {
						caps[c] = true
					}
				}
			}
		}
		for _, r := range h.native {
			if r.field != s.Field {
				continue
			}
			report := reports["recog"]
			report.InputAvailable++
			reports["recog"] = report
			m := r.fp.Match(s.Value)
			if !m.Matched || len(m.Errors) > 0 {
				continue
			}
			kind := m.Values["hw.device"]
			model := m.Values["hw.product"]
			brand := m.Values["hw.vendor"]
			// TLS issuer/subject, DHCP and shared vendor web servers do not prove chassis type.
			if strings.HasPrefix(s.Field, "tls_") || strings.HasPrefix(s.Field, "dhcp_") {
				kind = ""
				model = ""
			}
			if (strings.EqualFold(brand, "Hikvision") || strings.Contains(strings.ToLower(s.Value), "hikvision")) && model == "" {
				kind = ""
			}
			record("recog", r.id, r.version, kind, model, brand, s, m.Values)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s := groupRefs[key]
		if s.Protocol != "snmp" {
			continue
		}
		for _, r := range h.snmp {
			m, available := r.Condition.match(groups[key])
			if available {
				report := reports[r.Source]
				report.InputAvailable++
				reports[r.Source] = report
			}
			if !m || !available {
				continue
			}
			model := ""
			if v := groups[key]["oid:"+strings.Trim(r.ModelOID, ".")]; r.ModelOID != "" && len(v) > 0 {
				model = v[0]
			}
			for _, ex := range r.Extractors {
				if len(groups[key][ex.Field]) > 0 {
					report := reports["librenms_hardware"]
					report.InputAvailable++
					reports["librenms_hardware"] = report
				}
				for _, v := range groups[key][ex.Field] {
					if ex.compiled == nil {
						if strings.TrimSpace(v) != "" {
							model = strings.TrimSpace(v)
						}
					} else {
						m := ex.compiled.FindStringSubmatch(v)
						idx := ex.compiled.SubexpIndex(ex.Capture)
						if len(m) > 0 && idx > 0 && idx < len(m) {
							model = strings.TrimSpace(m[idx])
						}
					}
					if model != "" {
						break
					}
				}
				if model != "" {
					break
				}
			}
			if model != "" && len(r.Extractors) > 0 {
				report := reports["librenms_hardware"]
				report.Matched++
				reports["librenms_hardware"] = report
			}
			record(r.Source, r.ID, r.Version, r.Type, model, "", s, map[string]string{"os.product": r.Name, "hw.product": model})
			// An extracted hardware model uses the same reviewed model catalog.
			if model != "" {
				for _, mr := range h.models {
					if mr.compiled.MatchString(model) {
						record(mr.Source, mr.ID, mr.Version, mr.Type, model, mr.Manufacturer, s, nil)
						for _, c := range mr.Capabilities {
							caps[c] = true
						}
					}
				}
			}
		}
	}
	list := func(m map[string]bool) []string {
		r := make([]string, 0, len(m))
		for k := range m {
			r = append(r, k)
		}
		sort.Strings(r)
		return r
	}
	// A multifunction printer is one chassis with a scanning capability.
	if types["printer"] && types["scanner"] {
		delete(types, "scanner")
		caps["scanning"] = true
	}
	if len(types) == 1 {
		out.Type = list(types)[0]
		out.TypeStatus = "identified"
	} else if len(types) > 1 {
		out.TypeStatus = "conflict"
		out.ConflictingTypes = list(types)
	} else if len(out.Sources) > 0 {
		out.TypeStatus = "candidate"
	}
	if len(models) == 1 {
		out.Model = list(models)[0]
		out.ModelStatus = "identified"
	} else if len(models) > 1 {
		out.ModelStatus = "conflict"
		out.ConflictingModels = list(models)
	}
	if len(brands) == 1 {
		out.Manufacturer = list(brands)[0]
	}
	out.Capabilities = list(caps)
	if len(out.Sources) > 512 {
		out.Incomplete = true
		out.Error = "hardware matches exceed 512 source results"
	}
	if out.Incomplete {
		out.Type = ""
		out.Model = ""
		out.TypeStatus = ""
		out.ModelStatus = ""
	}
	deferReports()
	return out
}

func hardwareModelField(field string) bool {
	switch field {
	case "sadp_model", "snmp_model", "ssdp_model", "dns_sd_model", "mdns_model", "printer_make_and_model", "onvif_model", "wsd_model", "bacnet_model", "cdp_platform":
		return true
	}
	return false
}

// SourceReport exposes import/execution counts and unsupported reasons without
// conflating those counts with site observations or identification accuracy.
func (h *HardwareCatalog) SourceReport() ([]HardwareSourceReport, []HardwareUnsupported) {
	r := h.Evaluate(HardwareInput{}, time.Now())
	return r.SourceReports, append([]HardwareUnsupported(nil), h.Unsupported...)
}
