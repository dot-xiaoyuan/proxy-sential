package sharedaccess

import (
	"sort"
	"time"
)

const BehaviorRuleVersion = "shared-behavior/v6"

type BehaviorRouterContext struct {
	AssessmentID string `json:"assessment_id,omitempty"`
	Brand        string `json:"brand,omitempty"`
	Model        string `json:"model,omitempty"`
	Role         string `json:"role,omitempty"`
	Status       string `json:"status,omitempty"`
	Confidence   int    `json:"confidence,omitempty"`
}

type BehaviorScoreComponent struct {
	Signal      string `json:"signal"`
	Score       int    `json:"score"`
	Explanation string `json:"explanation"`
}

type BehaviorAssessment struct {
	ObservationID   string                              `json:"observation_id"`
	SensorID        string                              `json:"sensor_id"`
	CampusID        string                              `json:"campus_id,omitempty"`
	AccessDomain    string                              `json:"access_domain,omitempty"`
	IP              string                              `json:"ip"`
	EndpointID      string                              `json:"endpoint_id,omitempty"`
	Status          string                              `json:"status"`
	Confidence      int                                 `json:"confidence"`
	SignalGroups    []string                            `json:"signal_groups"`
	Reasons         []string                            `json:"reasons"`
	Conflicts       []string                            `json:"conflicts"`
	CoverageState   string                              `json:"coverage_state"`
	RuleVersion     string                              `json:"rule_version"`
	FirstSeen       time.Time                           `json:"first_seen"`
	LastSeen        time.Time                           `json:"last_seen"`
	WindowStart     time.Time                           `json:"window_start"`
	WindowEnd       time.Time                           `json:"window_end"`
	ExpiresAt       time.Time                           `json:"expires_at"`
	Router          BehaviorRouterContext               `json:"router"`
	ScoreComponents []BehaviorScoreComponent            `json:"score_components"`
	FeatureSamples  map[string]map[string]FeatureSample `json:"feature_samples"`
	EventIDs        []string                            `json:"event_ids"`
}

// AssessBehavior deliberately separates observable NAT/shared-gateway behavior
// from account attribution. A result can be reviewed without becoming eligible
// for enforcement; policy code still requires authoritative identity and all
// existing shared-access gates.
func AssessBehavior(id, endpointID string, w Window, router BehaviorRouterContext) (BehaviorAssessment, bool) {
	result := BehaviorAssessment{
		ObservationID: id, SensorID: w.SensorID, CampusID: w.CampusID, AccessDomain: w.AccessDomain,
		IP: w.IP, EndpointID: endpointID, Status: "candidate", RuleVersion: BehaviorRuleVersion,
		WindowStart: w.From, WindowEnd: w.To, FirstSeen: w.From, LastSeen: w.LastObservedAt,
		ExpiresAt: w.To.Add(30 * 24 * time.Hour), Router: router, FeatureSamples: w.Samples,
		EventIDs: append([]string{}, w.EventIDs...), Conflicts: append([]string{}, w.Conflicts...),
		SignalGroups: []string{}, Reasons: []string{}, ScoreComponents: []BehaviorScoreComponent{},
	}
	if w.CoverageVerified && w.Complete && len(w.Conflicts) == 0 {
		result.CoverageState = "verified"
	} else if len(w.EventIDs) > 0 {
		result.CoverageState = "partial"
	} else {
		result.CoverageState = "unknown"
	}
	type signal struct {
		name        string
		values      []string
		score       int
		explanation string
	}
	signals := []signal{
		{"ua_os", w.UAOS, 30, "同一出口反复共现多个操作系统 User-Agent"},
		{"ttl_path", w.TTLPaths, 35, "同一出口反复共现多个归一化 TTL 路径"},
		{"tcp_stack", w.TCPStacks, 30, "同一出口反复共现多个 TCP SYN 协议栈指纹"},
		{"tls_stack", w.TLSStacks, 30, "同一出口反复共现多个 TLS 客户端指纹"},
		{"dhcp_stack", w.DHCPProfiles, 25, "同一出口反复共现多个 DHCP 协议栈"},
	}
	behaviorGroups := 0
	identityGroups := 0
	for _, item := range signals {
		if diversity(item.values) < 2 || !w.repeatedTogether(item.name, item.values) {
			continue
		}
		behaviorGroups++
		// TLS and TCP fingerprints vary across applications and operating-system
		// updates on one endpoint. They corroborate sharing, but do not by
		// themselves prove that multiple endpoint identities sit behind an IP.
		if item.name == "ua_os" || item.name == "ttl_path" || item.name == "dhcp_stack" {
			identityGroups++
		}
		result.Confidence += item.score
		result.SignalGroups = append(result.SignalGroups, item.name)
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{Signal: item.name, Score: item.score, Explanation: item.explanation})
	}
	if behaviorGroups < 2 || identityGroups == 0 {
		return BehaviorAssessment{}, false
	}
	routerStrong := false
	switch router.Status {
	case "confirmed":
		result.Confidence += 30
		routerStrong = true
		result.SignalGroups = append(result.SignalGroups, "router_identity")
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{Signal: "router_identity", Score: 30, Explanation: "已确认路由器画像与共享出口一致"})
	case "likely":
		if router.Role == "router" {
			result.Confidence += 20
			routerStrong = true
			result.SignalGroups = append(result.SignalGroups, "router_identity")
			result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{Signal: "router_identity", Score: 20, Explanation: "较可信路由器画像与共享出口一致"})
		}
	}
	if result.Confidence > 100 {
		result.Confidence = 100
	}
	sort.Strings(result.SignalGroups)
	if result.CoverageState != "verified" {
		if result.Confidence > 59 {
			result.Confidence = 59
		}
		result.Conflicts = append(result.Conflicts, "capture_coverage_incomplete")
		result.Reasons = append(result.Reasons, "采集链路尚未证明完整，仅保留候选观察")
		return result, true
	}
	if result.Confidence >= 60 {
		result.Status = "likely"
		result.Reasons = append(result.Reasons, "至少两类独立共享行为信号反复共现")
	}
	if result.Confidence >= 80 && (behaviorGroups >= 3 || routerStrong && behaviorGroups >= 2) {
		result.Status = "confirmed"
		result.Reasons = append(result.Reasons, "满足高置信度共享网关确认条件")
	}
	return result, true
}
