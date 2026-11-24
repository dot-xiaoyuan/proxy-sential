package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
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

func (s *DBStore) verifyOutlet(ctx context.Context, cfg sharedaccess.Config, w sharedaccess.Window, m sharedaccess.IdentityMapping, l outletLocator) (*outletBinding, error) {
	if l.ip == "" {
		return nil, nil
	}
	// Attribution describes an authenticated address. For this read the live
	// session and event channels matter; historical quarantined messages also
	// degrade the overall bridge used by the separate policy decision.
	if m.HealthBridgeID != "" {
		var live bool
		err := s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_bridge_runtime WHERE bridge_id=$1 AND heartbeat_at>=now()-interval '60 seconds' AND online_channel_state='healthy' AND event_channel_state='healthy' AND snapshot_state='healthy' AND event_consecutive_failures=0 AND snapshot_consecutive_failures=0 AND NOT queue_sample_error AND processing_queue=0 AND source_queue=0)`, m.HealthBridgeID).Scan(&live)
		if err != nil || !live {
			return nil, err
		}
		m.HealthBridgeID = ""
	}
	w.IP = l.ip
	sessions, err := s.SharedIdentitySessions(ctx, m, w.IP, w.From, w.To, l.period)
	if err != nil {
		return nil, err
	}
	binding := uniqueOutletSession(w, cfg, sessions)
	if binding != nil && binding.MAC == l.mac && binding.VLAN == l.vlan {
		return binding, nil
	}
	return nil, nil
}

func (s *DBStore) outletRouter(ctx context.Context, w sharedaccess.Window, l outletLocator) (sharedaccess.BehaviorRouterContext, error) {
	var r sharedaccess.BehaviorRouterContext
	err := s.pg.db.QueryRowContext(ctx, `SELECT r.assessment_id,r.role,r.status,r.confidence,r.brand,r.model FROM router_assessments r
 WHERE regexp_replace(lower(r.mac),'[^0-9a-f]','','g')=$1 AND r.mac<>'' AND r.role='router' AND r.status IN ('likely','confirmed')
 AND NOT r.ambiguous AND NOT r.brand_reference_only AND NOT r.infrastructure AND r.expires_at>$2 AND r.first_seen<=$2
 AND EXISTS(SELECT 1 FROM router_evidence_facts f WHERE f.assessment_id=r.assessment_id AND f.data->>'sensor_id'=$3 AND f.data->>'role'='router' AND (f.vlan='' OR f.vlan=$4) AND f.first_seen<=$2 AND f.expires_at>$2 AND NOT f.conflict AND NOT f.exclusion AND f.score>0 AND f.source_family<>'shared_gateway_behavior' AND coalesce(f.data->>'brand_reference_only','false')<>'true')
 ORDER BY r.status_rank DESC,r.confidence DESC,r.last_seen DESC,r.assessment_id LIMIT 1`, strings.ReplaceAll(l.mac, ":", ""), w.To, w.SensorID, l.vlan).Scan(&r.AssessmentID, &r.Role, &r.Status, &r.Confidence, &r.Brand, &r.Model)
	if err == sql.ErrNoRows {
		return r, nil
	}
	return r, err
}

func (s *DBStore) assessOutlet(ctx context.Context, cfg sharedaccess.Config, w sharedaccess.Window, item sharedaccess.BehaviorAssessment) (sharedaccess.BehaviorAssessment, error) {
	m, err := cfg.Mapping(w)
	if err != nil || !item.Current || len(w.EventIDs) == 0 || (len(w.TLSStacks) == 0 && w.GatewayMAC == "") {
		return item, nil
	}
	secondary := w.HasRepeatedFeature("ttl_path") && w.HasRepeatedFeature("tls_stack")
	l, _, err := s.locateOutlet(ctx, m, w.IP, "")
	if err != nil || l.ip == "" {
		return item, err
	}
	if w.MixedClientVLAN || !outletVLANMatches(m.Source, l.vlan, w.ClientOuterVLAN, w.ClientVLAN) || w.GatewayMAC != "" && w.GatewayMAC != l.mac {
		return item, nil
	}
	r, err := s.outletRouter(ctx, w, l)
	if err != nil || (r.AssessmentID == "" && !secondary && w.StrongAnchor == "") {
		return item, err
	}
	b, err := s.verifyOutlet(ctx, cfg, w, m, l)
	if err != nil || b == nil {
		return item, err
	}
	item.AccountID = b.Account
	item.EndpointID = "mac:" + b.MAC
	item.OutletEvidence, _ = json.Marshal(b)
	if r.AssessmentID != "" {
		item.Router = r
		item.Confidence = max(item.Confidence, min(59, r.Confidence))
		if !slices.Contains(item.SignalGroups, "router_identity") {
			item.SignalGroups = append(item.SignalGroups, "router_identity")
		}
		item.ScoreComponents = append(item.ScoreComponents, sharedaccess.BehaviorScoreComponent{Signal: "router_identity", Score: min(59, r.Confidence), Explanation: "认证会话的 MAC 命中独立路由器角色证据"})
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
	binding, err := s.verifyOutlet(ctx, cfg, w, m, l)
	return binding, true, err
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
