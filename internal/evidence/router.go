package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

type RouterAssociation struct {
	EndpointID string
	MAC        string
	Quality    string
	Ambiguous  bool
	Reason     string
}

type RouterOptions struct {
	AsOf       time.Time
	RuleSet    *fingerprint.RouterRuleSet
	Resolve    func(normalized.Event) RouterAssociation
	ShadowMode bool
}

type RouterEvidence struct {
	EvidenceID         string   `json:"evidence_id"`
	AssessmentID       string   `json:"assessment_id"`
	Kind               string   `json:"kind"`
	EndpointID         string   `json:"endpoint_id,omitempty"`
	IP                 string   `json:"ip,omitempty"`
	MAC                string   `json:"mac,omitempty"`
	VLAN               string   `json:"vlan,omitempty"`
	Brand              string   `json:"brand,omitempty"`
	Series             string   `json:"series,omitempty"`
	Model              string   `json:"model,omitempty"`
	Role               string   `json:"role,omitempty"`
	Source             string   `json:"source"`
	SourceFamily       string   `json:"source_family"`
	SourceEventType    string   `json:"source_event_type,omitempty"`
	RawValue           string   `json:"raw_value,omitempty"`
	Strength           string   `json:"strength"`
	Score              int      `json:"score"`
	RuleID             string   `json:"rule_id"`
	RuleVersion        string   `json:"rule_version"`
	Explanation        string   `json:"explanation"`
	Conflict           bool     `json:"conflict"`
	ConflictCode       string   `json:"conflict_code,omitempty"`
	Exclusion          bool     `json:"exclusion"`
	BrandReferenceOnly bool     `json:"brand_reference_only"`
	BrandAttribution   bool     `json:"brand_attribution"`
	AssociationQuality string   `json:"association_quality"`
	AssociationReason  string   `json:"association_reason,omitempty"`
	Ambiguous          bool     `json:"ambiguous"`
	Infrastructure     bool     `json:"infrastructure"`
	FirstSeen          string   `json:"first_seen"`
	LastSeen           string   `json:"last_seen"`
	ExpiresAt          string   `json:"expires_at"`
	Expired            bool     `json:"expired"`
	EventIDs           []string `json:"event_ids"`
}

type RouterScoreComponent struct {
	SourceFamily string `json:"source_family"`
	EvidenceID   string `json:"evidence_id"`
	Score        int    `json:"score"`
	Explanation  string `json:"explanation"`
}

type RouterAssessment struct {
	AssessmentID       string                 `json:"assessment_id"`
	EndpointID         string                 `json:"endpoint_id,omitempty"`
	IP                 string                 `json:"ip,omitempty"`
	MAC                string                 `json:"mac,omitempty"`
	VLANs              []string               `json:"vlans,omitempty"`
	Brand              string                 `json:"brand,omitempty"`
	Series             string                 `json:"series,omitempty"`
	Model              string                 `json:"model,omitempty"`
	Role               string                 `json:"role,omitempty"`
	Status             string                 `json:"status"`
	Confidence         int                    `json:"confidence"`
	IndependentSources int                    `json:"independent_sources"`
	Sources            []string               `json:"sources"`
	Infrastructure     bool                   `json:"infrastructure"`
	BrandReferenceOnly bool                   `json:"brand_reference_only"`
	BrandAttribution   bool                   `json:"brand_attribution"`
	AssociationQuality string                 `json:"association_quality"`
	Ambiguous          bool                   `json:"ambiguous"`
	ConfirmedRouter    bool                   `json:"confirmed_router"`
	RuleVersion        string                 `json:"rule_version"`
	FirstSeen          string                 `json:"first_seen"`
	LastSeen           string                 `json:"last_seen"`
	ExpiresAt          string                 `json:"expires_at"`
	Conflicts          []string               `json:"conflicts"`
	ScoreComponents    []RouterScoreComponent `json:"score_components"`
	Evidence           []RouterEvidence       `json:"evidence,omitempty"`
	// MergedRecords is populated by list queries when multiple incremental
	// assessments resolve to the same physical device. It is presentation
	// metadata and is not persisted in the assessment snapshot.
	MergedRecords int `json:"merged_records,omitempty"`
}

type RouterResult struct {
	RuleVersion string             `json:"rule_version"`
	ShadowMode  bool               `json:"shadow_mode"`
	Evidence    []RouterEvidence   `json:"evidence"`
	Assessments []RouterAssessment `json:"assessments"`
}

type routerEventAssociation struct {
	id, endpoint, ip, mac, vlan, quality, reason string
	ambiguous, infrastructure                    bool
}

func AnalyzeRouters(events []normalized.Event, opts RouterOptions) (RouterResult, error) {
	rules := opts.RuleSet
	if rules == nil {
		rules = fingerprint.DefaultRouterRuleSet()
	}
	ttl, err := time.ParseDuration(rules.Thresholds.EvidenceTTL)
	if err != nil {
		return RouterResult{}, err
	}
	associationWindow, err := time.ParseDuration(rules.Thresholds.AssociationWindow)
	if err != nil {
		return RouterResult{}, err
	}
	maxEventTime := time.Time{}
	for _, event := range events {
		if at, parseErr := time.Parse(time.RFC3339Nano, event.Timestamp); parseErr == nil && at.After(maxEventTime) {
			maxEventTime = at
		}
	}
	asOf := opts.AsOf
	if asOf.IsZero() {
		asOf = maxEventTime
	}
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}
	known := routerKnownAddresses(events, associationWindow)
	dedup := map[string]*RouterEvidence{}
	associations := map[string]routerEventAssociation{}

	for _, event := range events {
		at, parseErr := time.Parse(time.RFC3339Nano, event.Timestamp)
		if parseErr != nil {
			continue
		}
		association := routerAssociationFor(event, at, associationWindow, known, opts.Resolve)
		inputs := routerInputs(event)
		matches := rules.Match(inputs)
		family := routerSourceFamily(event)
		for _, match := range matches {
			score := routerMatchScore(family, match)
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{
				Kind: "router_signal", Brand: match.Brand, Series: match.Series, Model: match.Model, Role: match.Rule.Role,
				SourceFamily: family, RawValue: match.RawValue, Strength: match.Rule.Strength, Score: score,
				RuleID: match.Rule.ID, RuleVersion: match.Rule.Version, Explanation: match.Rule.Explanation,
				Conflict: match.Rule.Exclude, ConflictCode: match.Rule.ConflictCode, Exclusion: match.Rule.Exclude,
				BrandReferenceOnly: match.BrandOnly,
				BrandAttribution:   match.BrandAttribution,
			})
		}
		if family == "ssdp" && routerContainsAny(inputs, "ssdp_type", "InternetGatewayDevice", "WANDevice") {
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{Kind: "router_signal", Role: "router", SourceFamily: family, RawValue: firstRouterInput(inputs, "ssdp_type"), Strength: "medium", Score: 20, RuleID: "ssdp-internet-gateway", RuleVersion: rules.Version, Explanation: "SSDP InternetGatewayDevice 角色线索，不能单独确认路由器"})
		}
		if family == "lldp" && routerLLDPRouter(inputs) && len(matches) == 0 {
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{Kind: "router_signal", Role: "router", SourceFamily: family, RawValue: firstRouterInput(inputs, "lldp_capabilities"), Strength: "medium", Score: 30, RuleID: "lldp-router-capability", RuleVersion: rules.Version, Explanation: "LLDP router capability 角色线索，缺少品牌或型号"})
		}
		if family == "cdp" && routerCDPRouter(inputs) && len(matches) == 0 {
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{Kind: "router_signal", Role: "router", SourceFamily: family, RawValue: firstRouterInput(inputs, "cdp_capabilities"), Strength: "medium", Score: 30, RuleID: "cdp-router-capability", RuleVersion: rules.Version, Explanation: "CDP router capability 角色线索，缺少品牌或型号"})
		}
		if family == "first_hop_redundancy" && routerValidFirstHopEvidence(event) {
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{Kind: "router_signal", Role: "router", SourceFamily: family, RawValue: firstNonEmptyRouter(routerString(event.Payload["virtual_router_id"]), routerString(event.Payload["group"])), Strength: "strong", Score: 40, RuleID: "first-hop-redundancy-router-role", RuleVersion: rules.Version, Explanation: "VRRP/HSRP 首跳冗余协议广告，可确认设备承担路由角色"})
		}
		if routerLayer2SwitchEvidence(family, inputs) {
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{Kind: "conflict", Role: "switch", SourceFamily: family, RawValue: firstNonEmptyRouter(firstRouterInput(inputs, "cdp_capabilities"), firstRouterInput(inputs, "lldp_capabilities")), Strength: "strong", Score: -60, RuleID: "layer2-switch-capability", RuleVersion: rules.Version, Explanation: "链路发现协议仅声明二层交换能力，不应作为路由器候选", Conflict: true, ConflictCode: "infrastructure_switch", Exclusion: true})
		}
		if routerTerminalConflict(inputs) {
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{Kind: "conflict", Role: "endpoint", SourceFamily: "endpoint", RawValue: firstRouterInput(inputs, "user_agent"), Strength: "strong", Score: -35, RuleID: "endpoint-device-conflict", RuleVersion: rules.Version, Explanation: "手机、平板或 PC 终端特征与路由器判断冲突", Conflict: true, ConflictCode: "ordinary_endpoint"})
		}
		if family == "weak_stack" && (routerInt(event.Flow["ttl"]) > 0 || routerInt(event.Payload["ttl"]) > 0) {
			appendRouterEvidence(dedup, associations, association, event, at, ttl, asOf, RouterEvidence{Kind: "router_signal", SourceFamily: family, RawValue: fmt.Sprint(firstRouterValue(event.Flow["ttl"], event.Payload["ttl"])), Strength: "weak", Score: 5, RuleID: "weak-stack-ttl", RuleVersion: rules.Version, Explanation: "TTL/TCP 弱特征，只能作为辅助线索"})
		}
	}

	grouped := map[string][]RouterEvidence{}
	for _, item := range dedup {
		grouped[item.AssessmentID] = append(grouped[item.AssessmentID], *item)
	}
	result := RouterResult{RuleVersion: rules.Version, ShadowMode: true, Evidence: []RouterEvidence{}, Assessments: []RouterAssessment{}}
	for _, evidenceItems := range grouped {
		assessment, present := AggregateRouterEvidence(evidenceItems, rules, asOf)
		// Do not create router records from TTL/UA alone.
		if !present {
			continue
		}
		if assessment.ConfirmedRouter {
			confirmed := RouterEvidence{EvidenceID: stableRouterID("confirmed", assessment.AssessmentID, assessment.LastSeen, rules.Version), AssessmentID: assessment.AssessmentID, Kind: "confirmed_router", EndpointID: assessment.EndpointID, IP: assessment.IP, MAC: assessment.MAC, Brand: assessment.Brand, Series: assessment.Series, Model: assessment.Model, Role: "router", Source: "router_aggregator", SourceFamily: "derived", Strength: "strong", Score: assessment.Confidence, RuleID: "confirmed-router-threshold", RuleVersion: rules.Version, Explanation: "满足路由器确认阈值、独立来源和强证据要求", AssociationQuality: assessment.AssociationQuality, FirstSeen: assessment.FirstSeen, LastSeen: assessment.LastSeen, ExpiresAt: assessment.ExpiresAt, EventIDs: routerEvidenceIDs(evidenceItems)}
			assessment.Evidence = append(assessment.Evidence, confirmed)
			result.Evidence = append(result.Evidence, confirmed)
		}
		result.Assessments = append(result.Assessments, assessment)
		result.Evidence = append(result.Evidence, evidenceItems...)
	}
	sort.Slice(result.Assessments, func(i, j int) bool {
		if result.Assessments[i].Confidence != result.Assessments[j].Confidence {
			return result.Assessments[i].Confidence > result.Assessments[j].Confidence
		}
		return result.Assessments[i].AssessmentID < result.Assessments[j].AssessmentID
	})
	sort.Slice(result.Evidence, func(i, j int) bool {
		if result.Evidence[i].LastSeen != result.Evidence[j].LastSeen {
			return result.Evidence[i].LastSeen > result.Evidence[j].LastSeen
		}
		return result.Evidence[i].EvidenceID < result.Evidence[j].EvidenceID
	})
	return result, nil
}

func routerKnownAddresses(events []normalized.Event, window time.Duration) map[string][]routerAddressOwner {
	result := map[string][]routerAddressOwner{}
	for _, event := range events {
		mac := normalizeRouterMAC(routerString(event.Subject["mac"]))
		ip := routerString(event.Subject["ip"])
		at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if mac == "" || ip == "" || err != nil {
			continue
		}
		key := routerScope(event) + "|" + ip + "|" + routerString(event.Payload["vlan"])
		result[key] = append(result[key], routerAddressOwner{mac: mac, at: at, until: at.Add(window)})
	}
	return result
}

type routerAddressOwner struct {
	mac       string
	at, until time.Time
}

func routerAssociationFor(event normalized.Event, at time.Time, window time.Duration, known map[string][]routerAddressOwner, resolve func(normalized.Event) RouterAssociation) routerEventAssociation {
	endpoint := routerString(event.Subject["endpoint_id"])
	mac := normalizeRouterMAC(routerString(event.Subject["mac"]))
	ip := routerString(event.Subject["ip"])
	vlan := firstRouterString(event.Payload, "vlan")
	quality, reason, ambiguous := "", "", false
	if endpoint != "" {
		quality = "endpoint"
	} else if mac != "" {
		quality = "mac"
	} else if resolve != nil {
		resolved := resolve(event)
		endpoint, mac, quality, reason, ambiguous = resolved.EndpointID, normalizeRouterMAC(resolved.MAC), resolved.Quality, resolved.Reason, resolved.Ambiguous
	}
	if endpoint == "" && mac == "" {
		key := routerScope(event) + "|" + ip + "|" + vlan
		owners := map[string]bool{}
		for _, owner := range known[key] {
			if !at.Before(owner.at.Add(-window)) && at.Before(owner.until.Add(window)) {
				owners[owner.mac] = true
			}
		}
		if len(owners) == 1 {
			for owner := range owners {
				mac = owner
			}
			quality = "event_window_mac"
		} else {
			quality, ambiguous = "ip_vlan_window", true
			if len(owners) > 1 {
				reason = "同一 IP/VLAN 时间窗口存在多个 MAC"
			} else {
				reason = "缺少 MAC，未找到唯一事件时设备归属"
			}
		}
	}
	key := ""
	if endpoint != "" {
		key = "endpoint:" + endpoint
	} else if mac != "" {
		key = "mac:" + routerScope(event) + ":" + mac
	} else {
		bucket := at.Truncate(window).UTC().Format(time.RFC3339)
		key = "ip:" + routerScope(event) + ":" + ip + ":" + vlan + ":" + bucket
	}
	role := strings.ToLower(routerString(event.Subject["entity_role"]))
	infrastructure := role == "infrastructure" || role == "network_device" || routerBool(event.Payload["infrastructure"])
	return routerEventAssociation{id: stableRouterID("assessment", key), endpoint: endpoint, ip: ip, mac: mac, vlan: vlan, quality: quality, reason: reason, ambiguous: ambiguous, infrastructure: infrastructure}
}

func routerInputs(event normalized.Event) map[string][]string {
	result := map[string][]string{}
	add := func(key string, values ...any) {
		for _, value := range values {
			for _, text := range routerStrings(value) {
				if text != "" {
					result[key] = append(result[key], text)
				}
			}
		}
	}
	add("hostname", event.Payload["hostname"], event.Payload["client_fqdn"], event.Payload["device_name"], event.Payload["discovery_name"])
	add("vendor_class", event.Payload["vendor_class"])
	add("requested_options", event.Payload["requested_options"])
	add("software", event.Payload["software"], event.Payload["software_name"], event.Payload["name"], event.Payload["version"])
	add("lldp_system_name", event.Payload["system_name"], event.Payload["lldp_system_name"])
	add("lldp_system_description", event.Payload["system_description"], event.Payload["lldp_system_description"])
	add("lldp_capabilities", event.Payload["capabilities"], event.Payload["system_capabilities"])
	add("cdp_system_name", event.Payload["system_name"], event.Payload["device_id"])
	add("cdp_platform", event.Payload["platform"])
	add("cdp_software", event.Payload["software"])
	add("cdp_capabilities", event.Payload["capabilities"])
	add("ssdp_type", event.Payload["st"], event.Payload["nt"], event.Payload["usn"], event.Payload["device_type"])
	add("http_host", event.Payload["host"])
	add("http_server", event.Payload["server"])
	add("http_title", event.Payload["title"])
	add("tls_sni", event.Payload["sni"])
	add("tls_subject", event.Payload["subject"], event.Payload["certificate_subject"])
	add("tls_issuer", event.Payload["issuer"], event.Payload["certificate_issuer"])
	add("tls_san", event.Payload["san"], event.Payload["certificate_san"])
	add("user_agent", event.Payload["user_agent"])
	add("oui_vendor", event.Payload["oui_vendor"], event.Payload["vendor"])
	if mac := routerString(event.Subject["mac"]); mac != "" {
		identified := fingerprint.Default().Identify(mac)
		add("oui_vendor", identified.Vendor)
	}
	return result
}

func appendRouterEvidence(dedup map[string]*RouterEvidence, associations map[string]routerEventAssociation, association routerEventAssociation, event normalized.Event, at time.Time, ttl time.Duration, asOf time.Time, item RouterEvidence) {
	item.AssessmentID, item.EndpointID, item.IP, item.MAC, item.VLAN = association.id, association.endpoint, association.ip, association.mac, association.vlan
	item.Source, item.SourceEventType = event.Source, event.SourceEventType
	item.AssociationQuality, item.AssociationReason, item.Ambiguous, item.Infrastructure = association.quality, association.reason, association.ambiguous, association.infrastructure
	item.FirstSeen, item.LastSeen, item.ExpiresAt = at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano), at.Add(ttl).UTC().Format(time.RFC3339Nano)
	item.Expired = !asOf.Before(at.Add(ttl))
	item.EventIDs = []string{event.EventID}
	key := association.id + "|" + item.SourceFamily + "|" + item.RuleID + "|" + strings.ToLower(strings.TrimSpace(item.RawValue))
	item.EvidenceID = stableRouterID("router-evidence", key)
	associations[association.id] = mergeRouterAssociation(associations[association.id], association)
	if current := dedup[item.EvidenceID]; current != nil {
		if item.FirstSeen < current.FirstSeen {
			current.FirstSeen = item.FirstSeen
		}
		if item.LastSeen > current.LastSeen {
			current.LastSeen, current.ExpiresAt, current.Expired = item.LastSeen, item.ExpiresAt, item.Expired
		}
		if event.EventID != "" && !routerContains(current.EventIDs, event.EventID) && len(current.EventIDs) < 20 {
			current.EventIDs = append(current.EventIDs, event.EventID)
		}
		return
	}
	dedup[item.EvidenceID] = &item
}

// AggregateRouterEvidence rebuilds one assessment from durable evidence facts.
// It is intentionally collector-independent so an incremental worker can merge
// DHCP, LLDP and management-plane signals that arrived in different batches.
func AggregateRouterEvidence(items []RouterEvidence, rules *fingerprint.RouterRuleSet, asOf time.Time) (RouterAssessment, bool) {
	if rules == nil {
		rules = fingerprint.DefaultRouterRuleSet()
	}
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}
	filtered := make([]RouterEvidence, 0, len(items))
	association := routerEventAssociation{}
	assessmentID := ""
	for _, item := range items {
		if item.Kind == "confirmed_router" || item.AssessmentID == "" {
			continue
		}
		if assessmentID == "" {
			assessmentID = item.AssessmentID
		}
		if item.AssessmentID != assessmentID {
			continue
		}
		if expires, err := time.Parse(time.RFC3339Nano, item.ExpiresAt); err == nil {
			item.Expired = !asOf.Before(expires)
		}
		association = mergeRouterAssociation(association, routerEventAssociation{
			id:             assessmentID,
			endpoint:       item.EndpointID,
			ip:             item.IP,
			mac:            item.MAC,
			vlan:           item.VLAN,
			quality:        item.AssociationQuality,
			reason:         item.AssociationReason,
			ambiguous:      item.Ambiguous,
			infrastructure: item.Infrastructure,
		})
		filtered = append(filtered, item)
	}
	if assessmentID == "" || !routerHasPositiveIdentityEvidence(filtered) {
		return RouterAssessment{}, false
	}
	return buildRouterAssessment(assessmentID, association, filtered, rules, asOf), true
}

func buildRouterAssessment(id string, association routerEventAssociation, items []RouterEvidence, rules *fingerprint.RouterRuleSet, asOf time.Time) RouterAssessment {
	sort.Slice(items, func(i, j int) bool { return items[i].LastSeen < items[j].LastSeen })
	assessment := RouterAssessment{AssessmentID: id, EndpointID: association.endpoint, IP: association.ip, MAC: association.mac, Status: "candidate", Role: "unknown", Infrastructure: association.infrastructure, AssociationQuality: association.quality, Ambiguous: association.ambiguous, RuleVersion: rules.Version, Evidence: items, Sources: []string{}, Conflicts: []string{}, ScoreComponents: []RouterScoreComponent{}}
	sharedGatewayRole := false
	for _, item := range items {
		if item.Expired {
			continue
		}
		sharedGatewayRole = sharedGatewayRole || item.SourceFamily == "shared_gateway_behavior" && item.Role == "router" && !item.Exclusion
	}
	bestByFamily := map[string]RouterEvidence{}
	vlans, conflicts := map[string]bool{}, map[string]bool{}
	strong, exclusion, verifiedBrand, attributedBrand := false, false, false, false
	brandRank := 0
	for _, item := range items {
		if item.VLAN != "" {
			vlans[item.VLAN] = true
		}
		if assessment.FirstSeen == "" || item.FirstSeen < assessment.FirstSeen {
			assessment.FirstSeen = item.FirstSeen
		}
		if item.LastSeen > assessment.LastSeen {
			assessment.LastSeen, assessment.ExpiresAt = item.LastSeen, item.ExpiresAt
		}
		// Retain expired identity metadata for audit/history. Current list
		// eligibility is checked against live role facts, so stale metadata can no
		// longer make an expired router visible.
		if item.Exclusion {
			assessment.Role = item.Role
		}
		if !item.Exclusion && (item.Role == "router" || item.Role == "ap") && assessment.Role == "unknown" {
			assessment.Role = item.Role
		}
		itemBrandRank := 0
		if item.Brand != "" {
			itemBrandRank = 1
			if item.BrandAttribution {
				itemBrandRank = 2
			}
			if !item.BrandReferenceOnly {
				itemBrandRank = 3
			}
		}
		if itemBrandRank >= brandRank && itemBrandRank > 0 {
			assessment.Brand, brandRank = item.Brand, itemBrandRank
		}
		if item.Brand != "" && !item.BrandReferenceOnly && !item.Expired {
			verifiedBrand = true
		}
		if item.Brand != "" && item.BrandAttribution && !item.Expired {
			attributedBrand = true
			assessment.BrandAttribution = true
		}
		if item.Series != "" && !item.BrandReferenceOnly {
			assessment.Series = item.Series
		}
		if item.Model != "" && !item.BrandReferenceOnly {
			assessment.Model = item.Model
		}
		if item.Expired {
			continue
		}
		overriddenRoleConflict := false
		if sharedGatewayRole && (item.Exclusion && item.ConflictCode == "infrastructure_ap" || item.ConflictCode == "ordinary_endpoint") {
			overriddenRoleConflict = true
		}
		if overriddenRoleConflict {
			continue
		}
		if item.Conflict {
			conflicts[firstNonEmptyRouter(item.ConflictCode, item.Explanation)] = true
		}
		if item.Exclusion {
			exclusion = true
		}
		current, exists := bestByFamily[item.SourceFamily]
		if !exists || current.Score >= 0 && (item.Score > current.Score || item.Score < 0) {
			bestByFamily[item.SourceFamily] = item
		}
		if item.Strength == "strong" && item.Score > 0 && !item.BrandReferenceOnly {
			strong = true
		}
	}
	if sharedGatewayRole {
		assessment.Role = "router"
	}
	if assessment.Role == "router" && sharedGatewayRole && !verifiedBrand && !attributedBrand {
		// A vendor reference seen in a phone application certificate, DHCP
		// class, or OUI is not a verified manufacturer for a separately
		// confirmed router role.
		assessment.Brand, assessment.Series, assessment.Model = "", "", ""
	}
	for vlan := range vlans {
		assessment.VLANs = append(assessment.VLANs, vlan)
	}
	sort.Strings(assessment.VLANs)
	positiveSources := 0
	weakScore := 0
	for family, item := range bestByFamily {
		if item.Score > 0 {
			if family == "weak_stack" {
				weakScore += item.Score
				continue
			}
			if !item.BrandReferenceOnly {
				positiveSources++
			}
			assessment.Sources = append(assessment.Sources, family)
		}
		assessment.Confidence += item.Score
		assessment.ScoreComponents = append(assessment.ScoreComponents, RouterScoreComponent{SourceFamily: family, EvidenceID: item.EvidenceID, Score: item.Score, Explanation: item.Explanation})
	}
	if weakScore > 10 {
		weakScore = 10
	}
	assessment.Confidence += weakScore
	if association.infrastructure {
		conflicts["infrastructure_role"] = true
	}
	if association.ambiguous {
		conflicts["ambiguous_association"] = true
	}
	if assessment.Confidence < 0 {
		assessment.Confidence = 0
	}
	if assessment.Confidence > 100 {
		assessment.Confidence = 100
	}
	assessment.IndependentSources = positiveSources
	sort.Strings(assessment.Sources)
	for conflict := range conflicts {
		assessment.Conflicts = append(assessment.Conflicts, conflict)
	}
	sort.Strings(assessment.Conflicts)
	if assessment.Confidence >= rules.Thresholds.LikelyMin {
		assessment.Status = "likely"
	}
	canConfirm := assessment.Confidence >= rules.Thresholds.ConfirmedMin && positiveSources >= rules.Thresholds.ConfirmedSourcesMin && strong && !association.ambiguous && !association.infrastructure && !exclusion && assessment.Role == "router"
	if canConfirm {
		assessment.Status, assessment.ConfirmedRouter = "confirmed", true
	}
	assessment.BrandReferenceOnly = assessment.Brand != "" && assessment.Model == "" && assessment.Role != "router"
	return assessment
}

func routerSourceFamily(event normalized.Event) string {
	kind := strings.ToLower(firstNonEmptyRouter(event.SourceEventType, routerString(event.Payload["origin"]), event.Type))
	switch kind {
	case "dhcp":
		return "dhcp"
	case "software":
		// Zeek emits DHCP::CLIENT software from the same DHCP vendor-class
		// option. Treating it as independent evidence would double-count one
		// packet and can incorrectly promote a device to confirmed.
		if strings.EqualFold(routerString(event.Payload["software_type"]), "DHCP::CLIENT") {
			return "dhcp"
		}
		return "software"
	case "lldp":
		return "lldp"
	case "cdp":
		return "cdp"
	case "ssdp":
		return "ssdp"
	case "vrrp", "hsrp":
		return "first_hop_redundancy"
	case "http":
		return "http_management"
	case "ssl", "tls", "x509", "quic":
		return "tls_management"
	case "ttl", "conn", "flow", "dns":
		return "weak_stack"
	default:
		if len(routerStrings(event.Payload["oui_vendor"])) > 0 || len(routerStrings(event.Payload["vendor"])) > 0 {
			return "oui"
		}
		return kind
	}
}

func routerMatchScore(family string, match fingerprint.RouterRuleMatch) int {
	if match.Rule.Exclude {
		return match.Rule.Score
	}
	if match.BrandOnly {
		return 10
	}
	switch family {
	case "dhcp":
		if match.Rule.Score > 55 {
			return match.Rule.Score
		}
		return 55
	case "software":
		return 50
	case "lldp", "cdp":
		return 55
	case "ssdp":
		return 20
	case "http_management", "tls_management":
		return 30
	case "oui":
		return 10
	case "weak_stack":
		return 5
	default:
		return match.Rule.Score
	}
}

func routerHasPositiveIdentityEvidence(items []RouterEvidence) bool {
	for _, item := range items {
		if item.Score > 0 && item.SourceFamily != "weak_stack" || item.Exclusion {
			return true
		}
	}
	return false
}

func routerLLDPRouter(inputs map[string][]string) bool {
	return routerContainsAny(inputs, "lldp_capabilities", "router", "routing")
}

func routerCDPRouter(inputs map[string][]string) bool {
	return routerContainsAny(inputs, "cdp_capabilities", "router", "routing")
}

func routerLayer2SwitchEvidence(family string, inputs map[string][]string) bool {
	switch family {
	case "cdp":
		return routerContainsAny(inputs, "cdp_capabilities", "switch") && !routerCDPRouter(inputs)
	case "lldp":
		return routerContainsAny(inputs, "lldp_capabilities", "bridge") && !routerLLDPRouter(inputs)
	default:
		return false
	}
}

func routerValidFirstHopEvidence(event normalized.Event) bool {
	kind := strings.ToLower(firstNonEmptyRouter(event.SourceEventType, routerString(event.Payload["origin"]), event.Type))
	destination := routerString(event.Flow["dst_ip"])
	switch kind {
	case "vrrp":
		version := routerInt(event.Payload["version"])
		virtualRouterID := routerInt(event.Payload["virtual_router_id"])
		return (destination == "224.0.0.18" || strings.EqualFold(destination, "ff02::12")) && (version == 2 || version == 3) && virtualRouterID >= 1 && virtualRouterID <= 255
	case "hsrp":
		opcode := routerInt(event.Payload["opcode"])
		state := routerInt(event.Payload["state"])
		return destination == "224.0.0.2" && routerInt(event.Payload["udp_port"]) == 1985 && routerInt(event.Payload["version"]) == 0 && opcode >= 0 && opcode <= 2 && routerValidHSRPState(state)
	default:
		return false
	}
}

func routerValidHSRPState(value int) bool {
	switch value {
	case 0, 1, 2, 4, 8, 16:
		return true
	default:
		return false
	}
}

func routerTerminalConflict(inputs map[string][]string) bool {
	for _, value := range inputs["user_agent"] {
		lower := strings.ToLower(value)
		for _, marker := range []string{"android", "iphone", "ipad", "windows nt", "macintosh"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

func routerContainsAny(inputs map[string][]string, key string, needles ...string) bool {
	for _, value := range inputs[key] {
		for _, needle := range needles {
			if strings.Contains(strings.ToLower(value), strings.ToLower(needle)) {
				return true
			}
		}
	}
	return false
}

func firstRouterInput(inputs map[string][]string, key string) string {
	if len(inputs[key]) > 0 {
		return inputs[key][0]
	}
	return ""
}

func routerScope(event normalized.Event) string {
	return firstNonEmptyRouter(routerString(event.Observer["sensor_id"]), "default") + ":" + firstNonEmptyRouter(routerString(event.Subject["campus_id"]), routerString(event.Payload["campus_id"]), "default")
}

func routerStrings(value any) []string {
	switch item := value.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(item) == "" {
			return nil
		}
		return []string{strings.TrimSpace(item)}
	case []string:
		return item
	case []any:
		out := make([]string, 0, len(item))
		for _, value := range item {
			out = append(out, routerStrings(value)...)
		}
		return out
	default:
		return []string{strings.TrimSpace(fmt.Sprint(item))}
	}
}

func routerString(value any) string {
	values := routerStrings(value)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func firstRouterString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := routerString(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeRouterMAC(value string) string {
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 || parsed.String() == "00:00:00:00:00:00" {
		return ""
	}
	return parsed.String()
}

func routerInt(value any) int {
	var result int
	_, _ = fmt.Sscan(fmt.Sprint(value), &result)
	return result
}

func routerBool(value any) bool {
	text := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
	return text == "true" || text == "1" || text == "yes"
}

func firstRouterValue(values ...any) any {
	for _, value := range values {
		if value != nil && fmt.Sprint(value) != "" {
			return value
		}
	}
	return ""
}

func stableRouterID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func mergeRouterAssociation(current, incoming routerEventAssociation) routerEventAssociation {
	if current.id == "" {
		return incoming
	}
	if current.endpoint == "" {
		current.endpoint = incoming.endpoint
	}
	if current.mac == "" {
		current.mac = incoming.mac
	}
	if current.ip == "" || incoming.ip != "" {
		current.ip = incoming.ip
	}
	if current.vlan == "" || incoming.vlan != "" {
		current.vlan = incoming.vlan
	}
	current.infrastructure = current.infrastructure || incoming.infrastructure
	current.ambiguous = current.ambiguous || incoming.ambiguous
	if current.quality == "" || incoming.quality == "endpoint" || incoming.quality == "mac" && current.quality != "endpoint" {
		current.quality = incoming.quality
	}
	if incoming.reason != "" {
		current.reason = incoming.reason
	}
	return current
}

func routerContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func routerEvidenceIDs(items []RouterEvidence) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.EvidenceID)
	}
	sort.Strings(result)
	return result
}

func firstNonEmptyRouter(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
