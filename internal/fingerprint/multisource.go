package fingerprint

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed data/multisource-catalog.json
var embeddedCatalog []byte

//go:embed data/multisource-provenance.json
var embeddedProvenance []byte

type FingerprintSource struct {
	Kind             string         `json:"kind,omitempty"`
	LicenseFiles     []string       `json:"license_files"`
	SnapshotURL      string         `json:"snapshot_url"`
	UpstreamCount    int            `json:"upstream_count"`
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	URL              string         `json:"url"`
	Version          string         `json:"version"`
	License          string         `json:"license"`
	Checksum         string         `json:"checksum"`
	ConverterVersion string         `json:"converter_version"`
	Status           string         `json:"status"`
	Reason           string         `json:"reason,omitempty"`
	RawCount         int            `json:"raw_count"`
	ConditionCount   int            `json:"condition_count"`
	ExecutableCount  int            `json:"executable_count"`
	ModelCount       int            `json:"model_count"`
	Dispositions     map[string]int `json:"dispositions"`
	Protocols        []string       `json:"protocols"`
	Categories       []string       `json:"categories"`
}
type FingerprintCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	compiled *regexp.Regexp
}
type FingerprintExample struct {
	Values map[string]string `json:"values"`
	Match  bool              `json:"match"`
}
type SourceRule struct {
	OriginalType    string                 `json:"original_type,omitempty"`
	HardwareVersion string                 `json:"hardware_version,omitempty"`
	ID              string                 `json:"id"`
	SourceID        string                 `json:"source_id"`
	OriginalID      string                 `json:"original_id"`
	Version         string                 `json:"version"`
	Name            string                 `json:"name"`
	Protocol        string                 `json:"protocol"`
	Direction       string                 `json:"direction"`
	Conditions      []FingerprintCondition `json:"conditions"`
	Brand           string                 `json:"brand,omitempty"`
	Model           string                 `json:"model,omitempty"`
	Role            string                 `json:"role,omitempty"`
	OS              string                 `json:"os,omitempty"`
	Status          string                 `json:"status"`
	Reason          string                 `json:"reason,omitempty"`
	Strength        string                 `json:"strength"`
	Examples        []FingerprintExample   `json:"examples"`
	DuplicateOf     string                 `json:"duplicate_of,omitempty"`
}
type SourceMatch struct {
	Observed  map[string]string `json:"observed,omitempty"`
	SourceID  string            `json:"source_id"`
	RuleID    string            `json:"rule_id"`
	Version   string            `json:"version"`
	Name      string            `json:"name"`
	Protocol  string            `json:"protocol"`
	Direction string            `json:"direction"`
	Fields    []string          `json:"fields"`
	Brand     string            `json:"brand,omitempty"`
	Model     string            `json:"model,omitempty"`
	Role      string            `json:"role,omitempty"`
	OS        string            `json:"os,omitempty"`
	Strength  string            `json:"strength"`
}
type Catalog struct {
	Version    string              `json:"version"`
	Sources    []FingerprintSource `json:"sources"`
	Rules      []SourceRule        `json:"rules"`
	usedFields map[string]bool
	cacheMu    sync.RWMutex
	cache      map[string][]SourceMatch
	index      map[string][]int
}

// Fields are directional standard-event fields, never collector-specific data.
var supportedCatalogFields = map[string]bool{"user_agent": true, "dhcp_vendor_class": true, "dhcp_requested_options": true, "hostname": true, "http_server": true, "http_title": true, "tls_subject": true, "tls_issuer": true, "tls_san": true, "mdns_model": true, "snmp_sysdescr": true, "snmp_sysoid": true, "snmp_model": true, "ssdp_model": true, "ssdp_manufacturer": true, "dns_sd_model": true, "ssh_banner": true, "sip_server": true, "sip_user_agent": true, "http_www_authenticate": true, "http_body": true, "favicon_md5": true, "tcp_signature": true}

// PrepareCatalog classifies every rule; it is used only by the offline converter.
// Runtime loading rejects unsupported enabled rules instead of silently dropping them.
func PrepareCatalog(c *Catalog) {
	seen := map[string]string{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Status != "converted" {
			continue
		}
		if err := compileSourceRule(r); err != nil {
			r.Status = "unsupported_syntax"
			r.Reason = err.Error()
			continue
		}
		valid := true
		for _, e := range r.Examples {
			v := map[string][]string{}
			for k, x := range e.Values {
				v[k] = []string{x}
			}
			if ruleMatches(*r, v) != e.Match {
				valid = false
				break
			}
		}
		if !valid {
			r.Status = "invalid_data"
			r.Reason = "上游回放样例与转换结果不一致"
			continue
		}
		raw, _ := json.Marshal(struct {
			C             []FingerprintCondition
			B, M, R, O, D string
		}{r.Conditions, r.Brand, r.Model, r.Role, r.OS, r.Direction})
		sum := sha256.Sum256(raw)
		key := hex.EncodeToString(sum[:])
		if original, ok := seen[key]; ok {
			r.Status = "duplicate"
			r.DuplicateOf = original
			r.Reason = "与已纳入规则的条件及输出相同"
		} else {
			seen[key] = r.ID
		}
	}
	recountCatalog(c)
}
func recountCatalog(c *Catalog) {
	for i := range c.Sources {
		s := &c.Sources[i]
		s.RawCount = 0
		s.ConditionCount = 0
		s.ExecutableCount = 0
		s.ModelCount = 0
		s.Dispositions = map[string]int{}
		models := map[string]bool{}
		protocols := map[string]bool{}
		roles := map[string]bool{}
		for _, r := range c.Rules {
			if r.SourceID != s.ID {
				continue
			}
			s.RawCount++
			s.ConditionCount += len(r.Conditions)
			s.Dispositions[r.Status]++
			if r.Status == "converted" {
				s.ExecutableCount++
			}
			if r.Status == "dictionary" && r.Model != "" {
				models[r.Brand+"\x00"+r.Model] = true
			}
			if r.Protocol != "" {
				protocols[r.Protocol] = true
			}
			if r.Role != "" {
				roles[r.Role] = true
			}
		}
		s.ModelCount = len(models)
		s.Protocols = sortedKeys(protocols)
		s.Categories = sortedKeys(roles)
		if s.ExecutableCount > 0 || s.ModelCount > 0 {
			s.Status = "loaded"
		} else if s.RawCount > 0 && s.Status != "license_required" {
			s.Status = "pending_adapter"
		}
	}
}
func sortedKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func compileSourceRule(r *SourceRule) error {
	if len(r.Conditions) == 0 {
		return fmt.Errorf("匹配条件为空")
	}
	for i := range r.Conditions {
		c := &r.Conditions[i]
		if !supportedCatalogFields[c.Field] {
			return fmt.Errorf("尚未适配标准字段 %s", c.Field)
		}
		if len(c.Value) > 16384 {
			return fmt.Errorf("表达式超过长度限制")
		}
		switch c.Operator {
		case "regex":
			rx, err := regexp.Compile(c.Value)
			if err != nil {
				return fmt.Errorf("RE2 不支持此表达式")
			}
			c.compiled = rx
		case "exact", "contains", "prefix", "oid_prefix":
		default:
			return fmt.Errorf("不支持匹配操作 %s", c.Operator)
		}
	}
	return nil
}
func LoadCatalog(data []byte) (*Catalog, error) {
	if len(data) == 0 {
		return &Catalog{Sources: []FingerprintSource{}, Rules: []SourceRule{}, index: map[string][]int{}}, nil
	}
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	c.index = map[string][]int{}
	c.usedFields = map[string]bool{}
	sources := map[string]bool{}
	ids := map[string]bool{}
	for _, s := range c.Sources {
		if s.ID == "" || sources[s.ID] || s.URL == "" || s.License == "" {
			return nil, fmt.Errorf("invalid fingerprint source %q", s.ID)
		}
		sources[s.ID] = true
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.ID == "" || ids[r.ID] || !sources[r.SourceID] || r.Version == "" {
			return nil, fmt.Errorf("invalid source rule %q", r.ID)
		}
		ids[r.ID] = true
		if r.Status != "converted" {
			continue
		}
		if err := compileSourceRule(r); err != nil {
			return nil, fmt.Errorf("%s: %w", r.ID, err)
		}
		for _, condition := range r.Conditions {
			c.usedFields[condition.Field] = true
		}
		c.index[r.Conditions[0].Field] = append(c.index[r.Conditions[0].Field], i)
	}
	recountCatalog(&c)
	return &c, nil
}
func ruleMatches(r SourceRule, values map[string][]string) bool {
	for _, c := range r.Conditions {
		found := false
		for _, v := range values[c.Field] {
			if v == "" || len(v) > 16384 {
				continue
			}
			switch c.Operator {
			case "exact":
				found = v == c.Value
			case "contains":
				found = strings.Contains(v, c.Value)
			case "prefix":
				found = strings.HasPrefix(v, c.Value)
			case "oid_prefix":
				a, b := strings.Trim(v, "."), strings.Trim(c.Value, ".")
				found = a == b || strings.HasPrefix(a, b+".")
			case "regex":
				found = c.compiled != nil && c.compiled.MatchString(v)
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (c *Catalog) Match(values map[string][]string) []SourceMatch {
	matches, _ := c.MatchWithStats(values)
	return matches
}

// MatchWithStats reports the size of the field-routed candidate set. The value
// is stable across cache hits, so storing it cannot rewrite an unchanged read
// model simply because another endpoint warmed the cache first.
func (c *Catalog) MatchWithStats(values map[string][]string) ([]SourceMatch, int) {
	out := []SourceMatch{}
	if c == nil {
		return out, 0
	}
	fields := make([]string, 0, len(values))
	for f, inputs := range values {
		if !c.usedFields[f] {
			continue
		}
		for _, input := range inputs {
			if input != "" && len(input) <= 16384 {
				fields = append(fields, f)
				break
			}
		}
	}
	sort.Strings(fields)
	if len(fields) == 0 {
		return out, 0
	}
	candidateCount := 0
	for _, field := range fields {
		candidateCount += len(c.index[field])
	}
	var keyBuilder strings.Builder
	for _, f := range fields {
		keyBuilder.WriteString(strconv.Itoa(len(f)))
		keyBuilder.WriteByte(':')
		keyBuilder.WriteString(f)
		for _, v := range values[f] {
			if v != "" && len(v) <= 16384 {
				keyBuilder.WriteString(strconv.Itoa(len(v)))
				keyBuilder.WriteByte(':')
				keyBuilder.WriteString(v)
			}
		}
		keyBuilder.WriteByte(';')
	}
	cacheKey := keyBuilder.String()
	if len(cacheKey) <= 4096 {
		c.cacheMu.RLock()
		cached, found := c.cache[cacheKey]
		c.cacheMu.RUnlock()
		if found {
			return cloneSourceMatches(cached), candidateCount
		}
	}
	evaluated := 0
	for _, f := range fields {
		for _, i := range c.index[f] {
			r := c.Rules[i]
			evaluated++
			if !ruleMatches(r, values) {
				continue
			}
			fs := []string{}
			for _, x := range r.Conditions {
				fs = append(fs, x.Field)
			}
			expand := func(value string) string {
				if !strings.Contains(value, "$") {
					return value
				}
				for _, condition := range r.Conditions {
					if condition.compiled == nil {
						continue
					}
					for _, input := range values[condition.Field] {
						if input == "" || len(input) > 16384 {
							continue
						}
						if indices := condition.compiled.FindStringSubmatchIndex(input); indices != nil {
							return string(condition.compiled.ExpandString(nil, value, input, indices))
						}
					}
				}
				return ""
			}
			observed := map[string]string{}
			for _, condition := range r.Conditions {
				for _, value := range values[condition.Field] {
					if ruleMatches(SourceRule{Conditions: []FingerprintCondition{condition}}, map[string][]string{condition.Field: {value}}) {
						sample := value
						if condition.Field == "http_body" {
							if condition.Operator == "contains" {
								sample = condition.Value
							} else if condition.compiled != nil {
								sample = condition.compiled.FindString(value)
							}
						}
						runes := []rune(sample)
						if len(runes) > 200 {
							sample = string(runes[:200]) + "…"
						}
						observed[condition.Field] = sample
						break
					}
				}
			}
			out = append(out, SourceMatch{SourceID: r.SourceID, RuleID: r.ID, Version: r.Version, Name: r.Name, Protocol: r.Protocol, Direction: r.Direction, Fields: fs, Brand: expand(r.Brand), Model: expand(r.Model), Role: r.Role, OS: expand(r.OS), Strength: r.Strength, Observed: observed})
		}
	}
	if len(cacheKey) <= 4096 && len(out) <= 32 {
		c.cacheMu.Lock()
		if len(c.cache) >= 512 {
			c.cache = map[string][]SourceMatch{}
		}
		if c.cache == nil {
			c.cache = map[string][]SourceMatch{}
		}
		c.cache[cacheKey] = cloneSourceMatches(out)
		c.cacheMu.Unlock()
	}
	return out, evaluated
}
func (l *Library) Catalog() *Catalog {
	if l == nil || l.catalog == nil {
		c, _ := LoadCatalog(nil)
		return c
	}
	return l.catalog
}
func (l *Library) LoadCatalog(data []byte) error {
	c, err := LoadCatalog(data)
	if err != nil {
		return err
	}
	l.catalog = c
	return nil
}

func catalogSignalValues(s Signals) map[string][]string {
	values := map[string][]string{"hostname": s.Hostnames, "user_agent": s.UserAgents, "dhcp_vendor_class": {s.DHCPVendorClass}, "dhcp_requested_options": {s.DHCPRequestedOptions}}
	for k, v := range s.ProtocolFields {
		values[k] = v
	}
	return values
}
func applySourceMatches(result *Result, matches []SourceMatch) {
	result.SourceMatches = matches
	// Multiple libraries observing one protocol are not independent votes.
	roles := map[string]bool{}
	brands := map[string]bool{}
	models := map[string]bool{}
	for _, m := range matches {
		if m.Strength != "self_report" {
			continue
		}
		// Client/runtime fingerprints describe the requester, not the hardware
		// hosting a service. Preserve them for inspection without promoting a
		// physical brand, model or role.
		clientOnly := false
		for _, field := range m.Fields {
			if field == "user_agent" || field == "sip_user_agent" || field == "ja3" || field == "ja4" || field == "tcp_signature" {
				clientOnly = true
				break
			}
		}
		if clientOnly {
			continue
		}
		if m.Role != "" {
			roles[m.Role] = true
		}
		if m.Brand != "" && !strings.Contains(m.Brand, "$") {
			brands[m.Brand] = true
		}
		if m.Model != "" && !strings.Contains(m.Model, "$") {
			models[m.Model] = true
		}
	}
	if len(roles) > 1 || (result.DeviceType != "" && len(roles) > 0 && !roles[result.DeviceType]) {
		result.Conflict = true
		result.ConflictDimensions = appendConflictDimension(result.ConflictDimensions, "device_type")
	}
	if len(roles) == 1 && result.DeviceType == "" {
		result.DeviceType = sortedKeys(roles)[0]
		result.DeviceTypeConfidence = .8
		result.Confidence = max(result.Confidence, .8)
		result.Source = "multisource"
	}
	if len(brands) == 1 && result.Brand == "" {
		result.Brand = sortedKeys(brands)[0]
		result.BrandConfidence = .8
	}
	if len(brands) > 1 || (result.Brand != "" && len(brands) > 0 && !brands[result.Brand]) {
		result.Conflict = true
		result.ConflictDimensions = appendConflictDimension(result.ConflictDimensions, "brand")
	}
	if len(models) == 1 && result.Model == "" {
		result.Model = sortedKeys(models)[0]
		result.ModelConfidence = .8
	}
	if len(models) > 1 || (result.Model != "" && len(models) > 0 && !models[result.Model]) {
		result.Conflict = true
		result.ConflictDimensions = appendConflictDimension(result.ConflictDimensions, "model")
	}
}

type CatalogQuery struct {
	Source, Search, Protocol, Role, Status string
	Page, PageSize                         int
}
type CatalogPage struct {
	Items    []SourceRule `json:"items"`
	Total    int          `json:"total"`
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
}

func (c *Catalog) Search(q CatalogQuery) CatalogPage {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.PageSize < 1 {
		q.PageSize = 25
	}
	if q.PageSize > 100 {
		q.PageSize = 100
	}
	out := CatalogPage{Items: []SourceRule{}, Page: q.Page, PageSize: q.PageSize}
	needle := strings.ToLower(q.Search)
	for _, r := range c.Rules {
		if q.Source != "" && r.SourceID != q.Source || q.Protocol != "" && r.Protocol != q.Protocol || q.Role != "" && r.Role != q.Role || q.Status != "" && r.Status != q.Status {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(r.Name+" "+r.Brand+" "+r.Model+" "+r.ID), needle) {
			continue
		}
		n := out.Total
		out.Total++
		if n >= (q.Page-1)*q.PageSize && len(out.Items) < q.PageSize {
			out.Items = append(out.Items, r)
		}
	}
	return out
}

// VerifyCatalogProvenance binds every distributed source to preserved input and license text.
func VerifyCatalogProvenance(catalogData, provenanceData []byte) error {
	c, err := LoadCatalog(catalogData)
	if err != nil {
		return err
	}
	var files map[string]string
	if err = json.Unmarshal(provenanceData, &files); err != nil {
		return err
	}
	for name := range files {
		if path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "..") || strings.Contains(name, "\\") {
			return fmt.Errorf("invalid provenance path %q", name)
		}
	}
	for _, source := range c.Sources {
		if source.RawCount == 0 {
			continue
		}
		if source.Version == "" || source.SnapshotURL == "" || len(source.LicenseFiles) == 0 {
			return fmt.Errorf("missing source provenance/license: %s", source.ID)
		}
		licenseMarkers := map[string][]string{"BSD-2-Clause": {"Redistribution and use", "THIS SOFTWARE"}, "GPL-2.0": {"GNU GENERAL PUBLIC LICENSE", "Version 2"}, "GPL-3.0": {"GNU GENERAL PUBLIC LICENSE", "Version 3"}, "LGPL-2.1": {"GNU LESSER GENERAL PUBLIC LICENSE", "Version 2.1"}, "CC-BY-SA-4.0": {"Attribution-ShareAlike 4.0"}, "MIT": {"Permission is hereby granted"}}
		markers, knownLicense := licenseMarkers[source.License]
		if !knownLicense {
			return fmt.Errorf("unreviewed distribution license: %s", source.ID)
		}
		licenseText := ""
		for _, name := range source.LicenseFiles {
			licenseText += files[name]
		}
		for _, marker := range markers {
			if !strings.Contains(strings.ToLower(licenseText), strings.ToLower(marker)) {
				return fmt.Errorf("license declaration mismatch: %s", source.ID)
			}
		}
		for _, name := range source.LicenseFiles {
			if !strings.HasPrefix(name, source.ID+"/") || len(files[name]) < 100 {
				return fmt.Errorf("missing source license: %s", name)
			}
		}
		keys := []string{}
		for name := range files {
			if strings.HasPrefix(name, source.ID+"/") {
				keys = append(keys, name)
			}
		}
		sort.Strings(keys)
		h := sha256.New()
		for _, key := range keys {
			sum := sha256.Sum256([]byte(files[key]))
			fmt.Fprintf(h, "%s%c%x\n", key, 0, sum)
		}
		if hex.EncodeToString(h.Sum(nil)) != source.Checksum {
			return fmt.Errorf("source checksum mismatch: %s", source.ID)
		}
	}
	return nil
}

// SourceDirectory also exposes the existing engines without reclassifying OUI or
// domain records as executable device rules. Legacy merged UA/project data has no
// per-source provenance, so its per-source count remains zero and is explained.
func SourceDirectory(status Status) []FingerprintSource {
	out := append([]FingerprintSource{}, status.SourceCatalog...)
	add := func(id, name, url, license, kind string, count int) {
		state := "registered"
		if count > 0 {
			state = "loaded"
		}
		out = append(out, FingerprintSource{ID: id, Name: name, URL: url, License: license, Version: status.Version, Status: state, Kind: kind, RawCount: count, Dispositions: map[string]int{"legacy_loaded": count}, Protocols: []string{}, Categories: []string{}, Reason: "沿用原识别引擎；此处数量独立于多来源可执行规则"})
	}
	add("ieee", "IEEE MA-L/MA-M/MA-S", "https://standards-oui.ieee.org/", "IEEE public registry terms", "oui", status.OUICount)
	add("uap-core", "uap-core", "https://github.com/ua-parser/uap-core", "Apache-2.0", "legacy_rules", 0)
	out[len(out)-1].Reason = "与自有 UA 规则合并存储；不推算各来源数量，原识别引擎继续运行"
	add("project", "项目自有规则", "internal://proxy-sentinel", "internal-rule", "legacy_rules", status.RuleCount+status.RouterRuleCount)
	out[len(out)-1].Reason = "包含旧包合并存储的 UA 规则及自有路由器规则；不计入外部转换规则数"
	add("fingerbank-historical", "Fingerbank 历史公开快照", "https://github.com/karottc/fingerbank", "ODbL-1.0/DbCL-1.0", "legacy_rules", status.DHCPRuleCount)
	for _, entry := range []struct{ id, name, url, license string }{{"nextdns", "NextDNS", "https://github.com/nextdns/native-tracking-domains", "MIT"}, {"hagezi", "HaGeZi", "https://github.com/hagezi/dns-blocklists", "GPL-3.0"}} {
		count := 0
		for _, d := range status.DomainSources {
			if strings.Contains(strings.ToLower(d.Name), entry.id) {
				count += d.RuleCount
			}
		}
		add(entry.id, entry.name, entry.url, entry.license, "domain", count)
	}
	for i := range out {
		if out[i].Kind != "" && out[i].Status == "registered" {
			out[i].Version = ""
		}
		key := out[i].ID
		if key == "fingerbank-historical" {
			key = "fingerbank public snapshot"
		}
		for _, s := range status.Sources {
			if strings.Contains(strings.ToLower(s.Name), key) {
				out[i].Version = s.Version
			}
		}
		if out[i].ID == "fingerbank-historical" && strings.HasPrefix(out[i].Version, "offline-bootstrap") {
			out[i].Name = "Fingerbank 兼容引导数据"
			out[i].Reason = "沿用现场 bootstrap 数据；完整历史快照未加载，与当前授权服务分开登记"
		}
	}
	return out
}

func cloneSourceMatches(in []SourceMatch) []SourceMatch {
	out := append([]SourceMatch{}, in...)
	for i := range out {
		out[i].Fields = append([]string{}, in[i].Fields...)
		if in[i].Observed != nil {
			out[i].Observed = map[string]string{}
			for k, v := range in[i].Observed {
				out[i].Observed[k] = v
			}
		}
	}
	return out
}

// LegacySignature lets catalog-only imports avoid the legacy all-device/domain
// backfill. Version labels are excluded; only execution-relevant content counts.
func (l *Library) LegacySignature() string {
	if l == nil {
		return ""
	}
	data, _ := json.Marshal(struct {
		OUI     map[string]string
		Rules   []Rule
		DHCP    map[string][]DHCPFingerprint
		Aliases map[string]string
		Domains []DomainSignature
	}{l.ouis, l.rules, l.dhcp, l.aliases, l.domains})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
