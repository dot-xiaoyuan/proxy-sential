package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
)

// The indexed snapshot locates an address. Replaying that address' authentication
// events independently catches logouts and reassignments after the snapshot.
type outletBinding struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"gateway_mac"`
	Account   string    `json:"account_id"`
	Session   string    `json:"session_id"`
	Source    string    `json:"source"`
	Sensor    string    `json:"sensor_id"`
	Campus    string    `json:"campus_id"`
	Domain    string    `json:"access_domain"`
	VLAN      string    `json:"vlan,omitempty"`
	Started   time.Time `json:"started_at"`
	Confirmed time.Time `json:"last_confirmed_at"`
	Snapshots []string  `json:"identity_snapshot_ids,omitempty"`
}

func uniqueOutletSession(w sharedaccess.Window, cfg sharedaccess.Config, sessions []policy.Session) *outletBinding {
	if w.From.Equal(w.To) && !w.From.IsZero() {
		w.From = w.From.Add(-time.Nanosecond)
	}
	account := sharedaccess.ObservationAccount(w, cfg, sessions)
	m, err := cfg.Mapping(w)
	if err != nil || account == "" {
		return nil
	}
	var binding *outletBinding
	for _, s := range sessions {
		if s.IP != w.IP || s.Source != m.Source || s.SensorID != m.IdentitySensorID || s.AccessDomain != m.IdentityAccessDomain || s.CampusID != m.IdentityCampusID || s.StartedAt.After(w.To) || (!s.EndedAt.IsZero() && !s.EndedAt.After(w.From)) {
			continue
		}
		mac, err := net.ParseMAC(s.MAC)
		if err != nil || !validUnicastMAC(mac.String()) || s.AccountID != account || s.ID == "" || s.IdentityIssue != "" || s.BindingConflict {
			return nil
		}
		if binding != nil && (binding.MAC != mac.String() || binding.Session != s.ID || binding.VLAN != s.VLAN) {
			return nil
		}
		binding = &outletBinding{IP: w.IP, MAC: mac.String(), Account: account, Session: s.ID, Source: s.Source, Sensor: s.SensorID, Campus: s.CampusID, Domain: s.AccessDomain, VLAN: s.VLAN, Started: s.StartedAt, Confirmed: s.ConfirmedAt, Snapshots: s.IdentitySnapshotIDs}
	}
	return binding
}

type outletLocator struct {
	ip, mac, vlan string
	period        int
}

// A gateway can have multiple addresses. Ambiguous matches are kept out of the
// IP-keyed work queue. Absence and conflict must remain distinguishable at the
// DHCP fallback boundary.
func (s *DBStore) locateOutlet(ctx context.Context, m sharedaccess.IdentityMapping, ip, mac string) (outletLocator, bool, error) {
	pred := "p.ip=$5"
	key := ip
	if mac != "" {
		pred = "regexp_replace(lower(coalesce(p.document->>'mac','')),'[^0-9a-f]','','g')=$5"
		key = strings.ReplaceAll(strings.ToLower(mac), ":", "")
	}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT p.ip,coalesce(p.document->>'mac',''),coalesce(p.document->>'vlan',''),coalesce(nullif(p.document->>'reconcile_interval_seconds','')::int,0)
 FROM account_identity_session_projection p WHERE p.source=$1 AND p.sensor_id=$2 AND p.campus_id=$3 AND p.access_domain=$4 AND `+pred+`
 AND coalesce(p.document->>'ended_at','')='' AND coalesce(p.document->>'mac','')<>'' LIMIT 2`, m.Source, m.IdentitySensorID, m.IdentityCampusID, m.IdentityAccessDomain, key)
	if err != nil {
		return outletLocator{}, false, err
	}
	defer rows.Close()
	var found outletLocator
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&found.ip, &found.mac, &found.vlan, &found.period); err != nil {
			return outletLocator{}, false, err
		}
	}
	if err = rows.Err(); err != nil {
		return outletLocator{}, false, err
	}
	hw, err := net.ParseMAC(found.mac)
	if count != 1 || err != nil || !validUnicastMAC(hw.String()) || found.period < 1 || found.period > 86400 {
		return outletLocator{}, count > 0, nil
	}
	found.mac = hw.String()
	return found, true, nil
}

func (s *DBStore) verifyOutlet(ctx context.Context, cfg sharedaccess.Config, w sharedaccess.Window, m sharedaccess.IdentityMapping, l outletLocator) (*outletBinding, string, error) {
	if l.ip == "" {
		return nil, "", nil
	}
	// The same authority timeline gates attribution and policy. A later queue
	// change cannot invalidate a covered packet or fill a gap in its history.
	w.IP = l.ip
	sessions, err := s.SharedIdentitySessions(ctx, m, w.IP, w.From, w.To, l.period)
	if err != nil {
		return nil, "", err
	}
	for _, session := range sessions {
		if session.IdentityIssue != "" {
			return nil, session.IdentityIssue, nil
		}
	}
	binding := uniqueOutletSession(w, cfg, sessions)
	if binding != nil && binding.MAC == l.mac && binding.VLAN == l.vlan {
		return binding, "", nil
	}
	return nil, "", nil
}

func routerRoleReviewReason(r sharedaccess.BehaviorRouterContext) string {
	if r.RoleSource == "dhcp" && r.Model != "" {
		switch r.RoleInput {
		case "hostname":
			return "型号仅来自 DHCP 主机名，缺少独立路由器角色证据"
		case "":
			return "DHCP 型号记录缺少匹配字段，无法确认路由器角色"
		}
	}
	return "路由器角色证据不足"
}

func (s *DBStore) outletRouter(ctx context.Context, w sharedaccess.Window, l outletLocator) (sharedaccess.BehaviorRouterContext, error) {
	var r sharedaccess.BehaviorRouterContext
	at := w.To
	if w.Activity != nil {
		at = w.Activity.At
	}
	err := s.pg.db.QueryRowContext(ctx, `SELECT r.assessment_id,r.role,r.status,r.confidence,r.brand,r.model,
 CASE WHEN f.explicit_role THEN f.evidence_id ELSE '' END,f.rule_id,f.source_family,f.input,f.event_id,f.value_excerpt,f.rule_version
 FROM router_assessments r JOIN LATERAL (
 SELECT f.evidence_id,f.rule_id,f.rule_version,left(coalesce(f.data->>'raw_value',''),512) AS value_excerpt,f.source_family,coalesce(f.data->>'model','') AS model,coalesce(f.data->>'input','') AS input,coalesce(f.data->'event_ids'->>0,'') AS event_id,
 (f.rule_id IN ('ssdp-advertised-internet-gateway','first-hop-redundancy-router-role') OR
 (f.data->>'strength'='strong' AND coalesce(f.data->>'model','')<>'' AND
 (f.source_family='dhcp' AND f.data->>'input'='vendor_class' OR f.source_family IN ('lldp','cdp','snmp_management','ssdp') AND f.data->>'input' IN ('lldp_system_description','cdp_platform','cdp_software','http_server','software')))) IS TRUE AS explicit_role
 FROM router_evidence_facts f WHERE f.assessment_id=r.assessment_id AND f.data->>'sensor_id'=$3 AND f.data->>'role'='router'
 AND lower(f.mac)=lower(r.mac) AND f.data->>'association_quality' IN ('mac','endpoint')
 AND (f.vlan='' OR f.vlan=$4 OR f.vlan=$5) AND f.first_seen<=$2 AND f.expires_at>$2 AND NOT f.conflict AND NOT f.exclusion AND f.score>0
 AND f.source_family NOT IN ('shared_gateway_behavior','client_fingerprint','weak_stack') AND coalesce(f.data->>'brand_reference_only','false')<>'true'
 ORDER BY explicit_role DESC,f.score DESC,f.last_seen DESC,f.evidence_id LIMIT 1) f ON true
 WHERE r.device_key='mac:'||$1 AND r.mac<>'' AND r.role='router'
 AND (r.status IN ('likely','confirmed') OR f.model<>'' OR f.explicit_role)
 AND NOT r.ambiguous AND NOT r.brand_reference_only AND NOT r.infrastructure AND r.expires_at>$2 AND r.first_seen<=$2
 AND NOT EXISTS (SELECT 1 FROM router_evidence_facts x WHERE x.assessment_id=r.assessment_id AND (x.conflict OR x.exclusion)
 AND coalesce(x.data->>'conflict_code','')<>'ordinary_endpoint' AND x.first_seen<=$2 AND x.expires_at>$2)
 ORDER BY f.explicit_role DESC,r.status_rank DESC,r.confidence DESC,r.assessment_id LIMIT 1`, l.mac, at, w.SensorID, l.vlan, strconv.Itoa(int(w.ClientVLAN))).Scan(&r.AssessmentID, &r.Role, &r.Status, &r.Confidence, &r.Brand, &r.Model, &r.RoleEvidenceID, &r.RoleRule, &r.RoleSource, &r.RoleInput, &r.RoleEventID, &r.RoleValueExcerpt, &r.RoleRuleVersion)
	if err == sql.ErrNoRows {
		return r, nil
	}
	return r, err
}

const (
	outletMissingBinding  = "缺少同窗认证绑定"
	outletBindingConflict = "认证绑定冲突或无效"
	outletMirrorMismatch  = "镜像 MAC 或 VLAN 与认证出口不符"
	outletUncovered       = "认证源记录未覆盖镜像证据时段"
	outletChangesPending  = "证据时段内的认证变更待处理"
	outletIndexPending    = "证据时段内的认证快照索引待完成"
)

func outletBindingReviewReason(issue string) string {
	switch issue {
	case "identity_source_interrupted", "identity_window_uncovered":
		return outletUncovered
	case "identity_processing_pending":
		return outletChangesPending
	case "identity_snapshot_index_pending":
		return outletIndexPending
	case "identity_snapshot_capture_conflict":
		return outletBindingConflict
	case "":
		return outletMissingBinding
	default:
		return "认证会话未覆盖证据时窗或身份源有缺口"
	}
}

func (s *DBStore) assessOutlet(ctx context.Context, cfg sharedaccess.Config, window *sharedaccess.Window, item sharedaccess.BehaviorAssessment) (sharedaccess.BehaviorAssessment, error) {
	w := *window
	m, err := cfg.Mapping(w)
	if err != nil || !item.Current || len(w.EventIDs) == 0 || (w.Activity == nil && len(w.TLSStacks) == 0 && w.GatewayMAC == "") {
		return item, nil
	}
	secondary := w.HasRepeatedFeature("ttl_path") && w.HasRepeatedFeature("tls_stack")
	l, exists, err := s.locateOutlet(ctx, m, w.IP, "")
	if err != nil {
		return item, err
	}
	observed := l
	if w.Activity != nil {
		observed.mac = w.Activity.MAC
	}
	var r sharedaccess.BehaviorRouterContext
	if observed.mac != "" {
		r, err = s.outletRouter(ctx, w, observed)
		if err != nil {
			return item, err
		}
	}
	if r.AssessmentID != "" {
		item.Router = r
		item.EndpointID = "mac:" + observed.mac
		item.Confidence = max(item.Confidence, min(59, r.Confidence))
		if !slices.Contains(item.SignalGroups, "router_identity") {
			item.SignalGroups = append(item.SignalGroups, "router_identity")
		}
		item.ScoreComponents = append(item.ScoreComponents, sharedaccess.BehaviorScoreComponent{Signal: "router_identity", Score: min(59, r.Confidence), Explanation: "镜像源 MAC 对应路由器画像"})
	} else if !secondary && w.StrongAnchor == "" {
		return item, nil
	}
	if l.ip == "" {
		item.ReviewReason = outletMissingBinding
		if exists {
			item.ReviewReason = outletBindingConflict
		}
		return item, nil
	}
	if w.MixedClientVLAN || !outletVLANMatches(m.Source, l.vlan, w.ClientOuterVLAN, w.ClientVLAN) || w.GatewayMAC != "" && w.GatewayMAC != l.mac || w.Activity != nil && w.Activity.MAC != l.mac {
		item.ReviewReason = outletMirrorMismatch
		return item, nil
	}
	identityWindow := w
	if r.AssessmentID != "" && w.Activity != nil {
		identityWindow.From, identityWindow.To, identityWindow.LastObservedAt = w.Activity.At, w.Activity.At, w.Activity.At
	}
	b, issue, err := s.verifyOutlet(ctx, cfg, identityWindow, m, l)
	if err != nil || b == nil {
		item.ReviewReason = outletBindingReviewReason(issue)
		return item, err
	}
	item.AccountID = b.Account
	item.EndpointID = "mac:" + b.MAC
	item.OutletEvidence, _ = json.Marshal(b)
	if r.AssessmentID != "" {
		switch {
		case r.RoleEvidenceID == "":
			item.ReviewReason = routerRoleReviewReason(r)
		case r.RoleEventID == "":
			item.ReviewReason = "路由器角色证据缺少原始事件引用"
		case w.Activity == nil:
			item.ReviewReason = "缺少认证出口的镜像活动"
		case l.vlan != "" && w.Activity.VLAN == 0:
			item.ReviewReason = "镜像活动缺少认证出口的 VLAN 标签"
		default:
			item.ReviewReason = "镜像活动与路由器证据待核验"
			window.RouterProof = &sharedaccess.RouterProof{AssessmentID: r.AssessmentID, RoleEvidenceID: r.RoleEvidenceID, RuleID: r.RoleRule, Account: b.Account, Session: b.Session, MAC: b.MAC}
			window.ID = policy.StableID(w.ID, r.AssessmentID, r.RoleEvidenceID, b.Account, b.Session, w.Activity.EventID)
			item.ObservationID = window.ID
		}
		item.Reasons = append([]string{"认证出口有镜像活动，认证 MAC 对应路由器画像"}, item.Reasons...)
	}
	return item, nil
}

func (s *DBStore) lookupGatewayBinding(ctx context.Context, cfg sharedaccess.Config, w sharedaccess.Window, mac string) (*outletBinding, bool, error) {
	m, err := cfg.Mapping(w)
	if err != nil {
		return nil, false, nil
	}
	l, exists, err := s.locateOutlet(ctx, m, w.IP, mac)
	if err != nil || !exists || l.ip == "" {
		return nil, exists, err
	}
	binding, _, err := s.verifyOutlet(ctx, cfg, w, m, l)
	return binding, true, err
}

// An authenticated school gateway can also advertise IGD or have mesh clients.
// Consult the registered MAC and the active role evidence before either verdict.
func (s *DBStore) excludeInfrastructureOutlet(ctx context.Context, w *sharedaccess.Window, item *sharedaccess.BehaviorAssessment) error {
	mac, at := w.GatewayMAC, w.To
	if w.RouterProof != nil && w.Activity != nil {
		mac, at = w.RouterProof.MAC, w.Activity.At
	}
	if mac == "" {
		return nil
	}
	var owned bool
	err := s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM endpoint_entities
 WHERE (endpoint_id='mac:'||$1 OR primary_mac IN ($1,upper($1))) AND merge_status='active'
 AND registration_status='registered' AND ownership_class='infrastructure')
 OR EXISTS(SELECT 1 FROM router_assessments r JOIN router_evidence_facts f USING(assessment_id)
 WHERE r.device_key='mac:'||$1 AND r.infrastructure AND f.data->>'infrastructure'='true'
 AND f.data->>'sensor_id'=$2 AND f.first_seen<=$3 AND f.expires_at>$3)`, strings.ToLower(mac), w.SensorID, at).Scan(&owned)
	if err != nil || !owned {
		return err
	}
	w.Conflicts = append(w.Conflicts, "infrastructure_ownership")
	w.RouterProof = nil
	item.Conflicts = w.Conflicts
	item.Status, item.ConfirmationBasis, item.ReviewReason = "candidate", "", "出口具有基础设施归属证据"
	return nil
}

// NCU encodes a QinQ pair as outer*10000+inner. A single visible tag
// cannot establish the missing outer domain of a double-tagged binding.
func outletVLANMatches(source, auth string, outer, inner uint16) bool {
	if auth == "" || inner == 0 {
		return true
	}
	value, err := strconv.Atoi(auth)
	if err != nil || value <= 0 {
		return false
	}
	if source == "ncu-srun4k" && value >= 10000 {
		return outer != 0 && value/10000 == int(outer) && value%10000 == int(inner)
	}
	return value == int(inner)
}

// AuthenticatedRouterSamplingKeys reads only active session coordinates.
// These hints affect output selection. Evidence and attribution are rechecked
// against event time by the shared-observation worker.
func (s *PostgresStore) AuthenticatedRouterSamplingKeys(ctx context.Context, sensor, campus, domain string) (map[sharedaccess.OutletKey]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT p.ip,r.mac
FROM shared_observation_mappings m
JOIN router_assessments r ON r.role='router' AND r.mac<>'' AND r.expires_at>now()
 AND NOT r.infrastructure AND NOT r.ambiguous AND NOT r.brand_reference_only
JOIN account_identity_session_projection p ON p.source=m.identity_source AND p.sensor_id=m.identity_sensor_id
 AND p.campus_id=m.identity_campus_id AND p.access_domain=m.identity_access_domain
 AND regexp_replace(lower(coalesce(p.document->>'mac','')),'[^0-9a-f]','','g')=replace(lower(r.mac),':','')
 AND coalesce(p.document->>'ended_at','')='' AND coalesce(p.document->>'mac','')<>'' AND p.ip<>''
WHERE m.active AND m.valid_from<=now() AND m.valid_until>now() AND m.sensor_id=$1 AND m.campus_id=$2 AND m.access_domain=$3
 AND NOT EXISTS (SELECT 1 FROM endpoint_entities e WHERE (e.endpoint_id='mac:'||lower(r.mac) OR e.primary_mac IN (lower(r.mac),upper(r.mac)))
   AND e.merge_status='active' AND e.registration_status='registered' AND e.ownership_class='infrastructure')
 AND EXISTS (SELECT 1 FROM router_evidence_facts f WHERE f.assessment_id=r.assessment_id AND f.expires_at>now()
   AND f.data->>'sensor_id'=m.sensor_id AND NOT f.conflict AND NOT f.exclusion AND f.score>0
   AND f.data->>'role'='router' AND f.source_family NOT IN ('client_fingerprint','weak_stack','shared_gateway_behavior')
   AND coalesce(f.data->>'brand_reference_only','false')<>'true')
ORDER BY p.ip,r.mac LIMIT 2048`, sensor, campus, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make(map[sharedaccess.OutletKey]struct{})
	for rows.Next() {
		var ip, mac string
		if err := rows.Scan(&ip, &mac); err != nil {
			return nil, err
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		hw, err := net.ParseMAC(mac)
		if err != nil || len(hw) != 6 || !validUnicastMAC(mac) {
			continue
		}
		keys[sharedaccess.OutletKey{IP: addr, MAC: [6]byte(hw)}] = struct{}{}
	}
	return keys, rows.Err()
}
