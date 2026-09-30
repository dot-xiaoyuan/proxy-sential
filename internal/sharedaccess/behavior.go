package sharedaccess

import (
	"sort"
	"time"
)

const BehaviorRuleVersion = "shared-behavior/v10"

type BehaviorRouterContext struct {
	AssessmentID string `json:"assessment_id,omitempty"`
	Brand        string `json:"brand,omitempty"`
	Model        string `json:"model,omitempty"`
	Role         string `json:"role,omitempty"`
	Status       string `json:"status,omitempty"`
	Confidence   int    `json:"confidence,omitempty"`
	// BrandAttribution is a vendor-specific control-plane identity. It may
	// corroborate diverse client stacks but never proves a gateway by itself.
	BrandAttribution bool `json:"brand_attribution,omitempty"`
}

type BehaviorScoreComponent struct {
	Signal      string `json:"signal"`
	Score       int    `json:"score"`
	Explanation string `json:"explanation"`
}

// KnownDevice is a conservative downstream identity derived from an explicit
// hardware model in passive application metadata. Generic operating systems,
// TLS fingerprints, and application names are intentionally excluded because
// they cannot be counted as physical devices.
type KnownDevice struct {
	IdentityID   string    `json:"identity_id"`
	Brand        string    `json:"brand,omitempty"`
	Model        string    `json:"model"`
	OSFamily     string    `json:"os_family,omitempty"`
	DeviceType   string    `json:"device_type,omitempty"`
	Observations int       `json:"observations"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

type BehaviorAssessment struct {
	ObservationID           string                              `json:"observation_id"`
	GenerationID            string                              `json:"generation_id,omitempty"`
	SensorID                string                              `json:"sensor_id"`
	CampusID                string                              `json:"campus_id,omitempty"`
	AccessDomain            string                              `json:"access_domain,omitempty"`
	IP                      string                              `json:"ip"`
	EndpointID              string                              `json:"endpoint_id,omitempty"`
	Status                  string                              `json:"status"`
	Confidence              int                                 `json:"confidence"`
	SignalGroups            []string                            `json:"signal_groups"`
	Reasons                 []string                            `json:"reasons"`
	Conflicts               []string                            `json:"conflicts"`
	CoverageState           string                              `json:"coverage_state"`
	RuleVersion             string                              `json:"rule_version"`
	FirstSeen               time.Time                           `json:"first_seen"`
	LastSeen                time.Time                           `json:"last_seen"`
	WindowStart             time.Time                           `json:"window_start"`
	WindowEnd               time.Time                           `json:"window_end"`
	ExpiresAt               time.Time                           `json:"expires_at"`
	Router                  BehaviorRouterContext               `json:"router"`
	ScoreComponents         []BehaviorScoreComponent            `json:"score_components"`
	FeatureSamples          map[string]map[string]FeatureSample `json:"feature_samples"`
	EventIDs                []string                            `json:"event_ids"`
	KnownDeviceCount        int                                 `json:"known_device_count"`
	KnownDeviceBasis        string                              `json:"known_device_basis,omitempty"`
	KnownDeviceWindow       string                              `json:"known_device_window,omitempty"`
	KnownDevices            []KnownDevice                       `json:"known_devices"`
	StrongAnchor            string                              `json:"strong_anchor,omitempty"`
	DeviceLowerBound        int                                 `json:"device_lower_bound"`
	ReferenceDeviceCount24h int                                 `json:"reference_device_count_24h,omitempty"`
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
		KnownDevices: []KnownDevice{},
	}
	if w.CoverageVerified && w.Complete && len(w.Conflicts) == 0 {
		result.CoverageState = "verified"
	} else if len(w.EventIDs) > 0 {
		result.CoverageState = "partial"
	} else {
		result.CoverageState = "unknown"
	}
	if diversity(w.AssociatedClients) >= 2 {
		result.Confidence = 90
		result.SignalGroups = append(result.SignalGroups, "confirmed_same_exit_endpoints", "ieee1905_association")
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{
			Signal: "ieee1905_association", Score: 90,
			Explanation: "IEEE 1905.1/EasyMesh 当前关联状态确认多个终端接入同一设备",
		})
		if (router.Status == "confirmed" || router.Status == "likely") && router.Role == "router" {
			result.SignalGroups = append(result.SignalGroups, "router_identity")
			result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{
				Signal: "router_identity", Score: 0, Explanation: "被动路由器画像与 EasyMesh 接入设备一致",
			})
		}
		sort.Strings(result.SignalGroups)
		if result.CoverageState != "verified" {
			result.Confidence = 59
			result.Conflicts = append(result.Conflicts, "capture_coverage_incomplete")
			result.Reasons = append(result.Reasons, "EasyMesh 关联可见，但采集连续性尚未验证")
			return result, true
		}
		result.Status = "confirmed"
		result.StrongAnchor = "ieee1905_association"
		result.DeviceLowerBound = diversity(w.AssociatedClients)
		result.Reasons = append(result.Reasons, "被动 EasyMesh 关联状态确认多个终端同时接入")
		return result, true
	}
	if diversity(w.PhysicalDeviceIdentities) >= 2 {
		result.Confidence = 90
		result.SignalGroups = append(result.SignalGroups, "coexisting_device_identities")
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{
			Signal: "coexisting_device_identities", Score: 90,
			Explanation: "当前窗口内至少两个稳定物理设备身份重复共现",
		})
		if (router.Status == "confirmed" || router.Status == "likely") && router.Role == "router" {
			result.SignalGroups = append(result.SignalGroups, "router_identity")
		}
		sort.Strings(result.SignalGroups)
		if result.CoverageState != "verified" {
			result.Confidence = 59
			result.Conflicts = append(result.Conflicts, "capture_coverage_incomplete")
			result.Reasons = append(result.Reasons, "多设备身份可见，但采集连续性尚未验证")
			return result, true
		}
		result.Status = "confirmed"
		result.StrongAnchor = "coexisting_device_identities"
		result.DeviceLowerBound = diversity(w.PhysicalDeviceIdentities)
		result.Reasons = append(result.Reasons, "当前窗口内至少两个稳定物理设备身份重复共现")
		return result, true
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
	for _, item := range signals {
		if diversity(item.values) < 2 || !w.repeatedTogether(item.name, item.values) {
			continue
		}
		behaviorGroups++
		// TLS and TCP fingerprints vary across applications and operating-system
		// updates on one endpoint. They corroborate sharing, but do not by
		// themselves prove that multiple endpoint identities sit behind an IP.
		result.Confidence += item.score
		result.SignalGroups = append(result.SignalGroups, item.name)
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{Signal: item.name, Score: item.score, Explanation: item.explanation})
	}
	if router.BrandAttribution && router.Brand != "" && behaviorGroups >= 2 {
		result.SignalGroups = append(result.SignalGroups, "vendor_gateway_identity")
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{
			Signal: "vendor_gateway_identity", Score: 0,
			Explanation: "专属厂商控制面身份仅作为协议栈差异的路由设备佐证",
		})
	}
	if behaviorGroups < 2 {
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
	// Protocol diversity is corroboration, not proof of multiple physical
	// terminals. Without a current-window strong anchor it must never confirm.
	if !routerStrong {
		result.Status = "candidate"
		if result.Confidence > 59 {
			result.Confidence = 59
		}
		result.Reasons = append(result.Reasons, "协议栈差异缺少当前多终端强锚点")
	} else if result.Confidence > 79 {
		result.Confidence = 79
	}
	return result, true
}
