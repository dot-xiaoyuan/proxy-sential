package sharedaccess

import (
	"slices"
	"sort"
	"time"
)

const BehaviorRuleVersion = "shared-behavior/v12"

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
	Current                 bool                                `json:"current"`
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
	models := w.CoexistingDeviceModels()
	if len(models) >= 2 && (w.repeatedTogether("tcp_stack", w.TCPStacks) || w.repeatedTogether("tls_stack", w.TLSStacks)) {
		result.Confidence = 90
		result.SignalGroups = append(result.SignalGroups, "coexisting_device_models")
		for _, corroboration := range []struct {
			name   string
			values []string
		}{{"tcp_stack", w.TCPStacks}, {"tls_stack", w.TLSStacks}} {
			if w.repeatedTogether(corroboration.name, corroboration.values) {
				result.SignalGroups = append(result.SignalGroups, corroboration.name)
				result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{Signal: corroboration.name, Score: 0, Explanation: "协议栈差异佐证当前型号共现，不单独计为物理设备"})
			}
		}
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{
			Signal: "coexisting_device_models", Score: 90,
			Explanation: "当前窗口内至少两个明确硬件型号重复共现，并有协议栈差异佐证",
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
		result.StrongAnchor = "coexisting_device_models"
		// Pairwise coexistence proves two devices, not that every model overlaps.
		result.DeviceLowerBound = 2
		result.Reasons = append(result.Reasons, "当前窗口内至少两个明确硬件型号重复共现，并有协议栈差异佐证")
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
		{"ttl_path", w.TTLPaths, 35, "同一方向反复共现不同推测初始 TTL 簇；仍需核验真实多终端接入"},
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
	// The dedicated collector is kernel-filtered to payload-free initial SYNs.
	// Its repeated TCP stack coexistence is useful as an operational lead, but
	// it cannot establish physical device count or become likely/confirmed by
	// itself. Ordinary packet-sidecar/application diversity keeps the stricter
	// multi-family gate below.
	dedicatedTCPClue := slices.Contains(w.Sources, "shared-syn-sidecar") &&
		diversity(w.TCPStacks) >= 3 && w.repeatedTogether("tcp_stack", w.TCPStacks)
	if behaviorGroups == 1 && dedicatedTCPClue {
		result.Status = "candidate"
		if result.Confidence > 40 {
			result.Confidence = 40
		}
		result.Reasons = append(result.Reasons, "专用 SYN 采集器发现同一出口反复共现多个 TCP 协议栈，仅作为共享复核候选")
		return result, true
	}
	if router.BrandAttribution && router.Brand != "" && behaviorGroups >= 2 {
		result.SignalGroups = append(result.SignalGroups, "vendor_gateway_identity")
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{
			Signal: "vendor_gateway_identity", Score: 0,
			Explanation: "专属厂商控制面身份仅作为协议栈差异的路由设备佐证",
		})
	}
	if behaviorGroups < 2 || !w.repeatedTogether("ua_os", w.UAOS) && !w.repeatedTogether("ttl_path", w.TTLPaths) && !w.repeatedTogether("dhcp_stack", w.DHCPProfiles) {
		return BehaviorAssessment{}, false
	}
	switch router.Status {
	case "confirmed":
		result.Confidence += 30
		result.SignalGroups = append(result.SignalGroups, "router_identity")
		result.ScoreComponents = append(result.ScoreComponents, BehaviorScoreComponent{Signal: "router_identity", Score: 30, Explanation: "已确认路由器画像与共享出口一致"})
	case "likely":
		if router.Role == "router" {
			result.Confidence += 20
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
	// Router identity and protocol diversity never establish downstream clients.
	// Keep weak observations below the discovery confirmation threshold.
	result.Status = "candidate"
	if result.Confidence > 59 {
		result.Confidence = 59
	}
	result.Reasons = []string{"协议差异仅供复核，缺少当前窗口的多终端接入证据"}
	return result, true
}
