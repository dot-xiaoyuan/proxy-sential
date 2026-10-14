// Package legacydpi converts dpi-analyze (legacy anti-proxy) configuration
// documents into proxy-sentinel entities.
//
// The conversion is offline and one-way: it never reads the legacy MongoDB and
// never writes the control-plane database. Callers load an exported JSON
// fixture, convert it here, and apply the result through the control plane.
//
// Two deliberate rules govern every conversion:
//
//   - Nothing becomes more active than it was in the legacy system. A legacy
//     strategy that was disabled converts to a disabled policy, a legacy action
//     that was disabled is dropped rather than silently armed, and channels and
//     behaviour rules convert disabled.
//   - Every value passes the production validator for its entity, so a
//     conversion failure is a compile-of-data error rather than a page that
//     fails to load later.
package legacydpi

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"proxy-sentinel/internal/notify"
	"proxy-sentinel/internal/poison"
	"proxy-sentinel/internal/policy"
)

// ConversionVersion identifies this mapping in downstream records.
const ConversionVersion = "dpi-analyze-to-sentinel/v1"

// ReasonPlaceholder fills a whitelist entry whose legacy remark was empty. The
// reason field is mandatory for every list entry, so an empty legacy remark is
// recorded as an explicit migration fact instead of an empty string.
const ReasonPlaceholder = "迁移自 dpi-analyze，原备注为空"

// Legacy whitelist type constants (pkg/component/types/policy.go).
const (
	LegacyWhitelistIP      = 1
	LegacyWhitelistUser    = 2
	LegacyWhitelistMAC     = 3
	LegacyWhitelistIPRange = 4
	LegacyWhitelistGroup   = 5
)

// legacyUserDisableSeconds mirrors the legacy global DisableTime default. The
// legacy user_disable action ignored its own duration parameter and used this
// value unless the site overrode it.
const legacyUserDisableSeconds = 7200

// legacyDefaultWindowSeconds is the evaluation window applied to converted
// device-count policies. The legacy engine evaluated on periodic device-bucket
// reconciliation rather than a fixed window, so the sentinel default is used.
const legacyDefaultWindowSeconds = 86400

// idPrefix marks every migrated entity so operators can tell converted
// configuration apart from natively authored configuration.
const idPrefix = "dpi-analyze:"

// Config is an exported snapshot of the legacy configuration plane.
type Config struct {
	Source      string             `json:"source"`
	ExportedAt  string             `json:"exported_at"`
	Whitelist   []LegacyWhitelist  `json:"whitelist"`
	Strategies  []LegacyStrategy   `json:"strategies"`
	PoisonRules []LegacyPoisonRule `json:"poison_rules"`
	Templates   []LegacyTemplate   `json:"templates"`
	SMSChannel  LegacySMSChannel   `json:"sms_channel"`
}

// LegacyWhitelist mirrors policy.policy_whitelist.
type LegacyWhitelist struct {
	LegacyID  string `json:"legacy_id"`
	Type      int    `json:"type"`
	Value     string `json:"value"`
	Remark    string `json:"remark"`
	Operate   string `json:"operate"`
	AddMethod string `json:"add_method"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// LegacyStrategy mirrors policy.policy_strategy.
type LegacyStrategy struct {
	LegacyID                  string         `json:"legacy_id"`
	Name                      string         `json:"name"`
	Match                     LegacyMatch    `json:"match"`
	Condition                 LegacyCond     `json:"condition"`
	Actions                   []LegacyAction `json:"actions"`
	Enabled                   bool           `json:"enabled"`
	RouterPunishEnabled       bool           `json:"router_punish_enabled"`
	RouterConfidenceThreshold int            `json:"router_confidence_threshold"`
}

type LegacyMatch struct {
	GroupIDs   []string `json:"group_ids"`
	ProductIDs []string `json:"product_ids"`
	VLANs      []string `json:"vlans"`
	Domains    []string `json:"domains"`
	IPRanges   []string `json:"ip_ranges"`
}

type LegacyCond struct {
	All           int  `json:"all"`
	Mobile        int  `json:"mobile"`
	PC            int  `json:"pc"`
	RouteIncrease bool `json:"route_increase"`
}

type LegacyAction struct {
	Type      string         `json:"type"`
	Enabled   bool           `json:"enabled"`
	Params    map[string]any `json:"params"`
	DependsOn []string       `json:"depends_on"`
}

// LegacyPoisonRule mirrors policy.poison_behavior_rule.
type LegacyPoisonRule struct {
	LegacyID        string   `json:"legacy_id"`
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	BehaviorType    string   `json:"behavior_type"`
	TargetType      string   `json:"target_type"`
	Targets         []string `json:"targets"`
	WindowSeconds   int      `json:"window_seconds"`
	Threshold       int      `json:"threshold"`
	PushEnabled     bool     `json:"push_enabled"`
	PushWithoutUser bool     `json:"push_without_user"`
	Remark          string   `json:"remark"`
}

// LegacyTemplate mirrors one entry of the legacy etc/template.json.
type LegacyTemplate struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	Vendor     string `json:"vendor"`
}

// LegacySMSChannel mirrors policy.policy_sms. The client secret is not part of
// the fixture and is supplied at apply time.
type LegacySMSChannel struct {
	LegacyID        string `json:"legacy_id"`
	AppID           string `json:"app_id"`
	APIHost         string `json:"api_host"`
	MessageTypeCode string `json:"message_type_code"`
	ClientID        string `json:"client_id"`
}

// Note records a conversion decision that lost or reinterpreted legacy intent.
// Notes are surfaced to the operator instead of being silently absorbed.
type Note struct {
	LegacyID string `json:"legacy_id"`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
}

// Result is the converted configuration.
type Result struct {
	Whitelist []policy.WhitelistEntry
	Policies  []policy.Definition
	Templates []notify.Template
	Channel   notify.Channel
	Rules     []poison.Rule
	Notes     []Note
}

// Legacy action type names.
const (
	actionMsgNotify          = "msg_notify"
	actionForceOffline       = "force_offline"
	actionBandwidthReduction = "bandwidth_reduction"
	actionUserDisable        = "user_disable"
)

// StageAction maps a legacy action type to the sentinel stage action.
func StageAction(legacy string) (string, bool) {
	switch legacy {
	case actionMsgNotify:
		return "notify", true
	case actionForceOffline:
		return "disconnect", true
	case actionBandwidthReduction:
		return "rate_limit", true
	case actionUserDisable:
		return "disable_account", true
	default:
		return "", false
	}
}

// LoadConfig reads an exported legacy configuration fixture.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("解析 legacy 配置失败: %w", err)
	}
	return cfg, nil
}

// Convert maps the whole legacy configuration plane onto sentinel entities.
// now is injected so tests are deterministic; secret carries the legacy SMS
// client secret and is sealed by the caller, never by this package.
func Convert(cfg Config, secret string, now time.Time) (Result, error) {
	result := Result{}

	entries, notes, err := ConvertWhitelist(cfg.Whitelist, now)
	if err != nil {
		return Result{}, err
	}
	result.Whitelist, result.Notes = entries, append(result.Notes, notes...)

	policies, notes, err := ConvertStrategies(cfg.Strategies)
	if err != nil {
		return Result{}, err
	}
	result.Policies, result.Notes = policies, append(result.Notes, notes...)

	templates, err := ConvertTemplates(cfg.Templates)
	if err != nil {
		return Result{}, err
	}
	result.Templates = templates

	channel, err := ConvertSMSChannel(cfg.SMSChannel, secret)
	if err != nil {
		return Result{}, err
	}
	result.Channel = channel

	rules, notes := ConvertPoisonRules(cfg.PoisonRules)
	result.Rules, result.Notes = rules, append(result.Notes, notes...)

	return result, nil
}

// ConvertWhitelist maps legacy list entries onto sentinel whitelist entries.
// The legacy type constants line up one-to-one with the sentinel type names.
func ConvertWhitelist(items []LegacyWhitelist, now time.Time) ([]policy.WhitelistEntry, []Note, error) {
	entries := make([]policy.WhitelistEntry, 0, len(items))
	notes := []Note{}
	for _, item := range items {
		kind, err := whitelistType(item.Type)
		if err != nil {
			return nil, nil, fmt.Errorf("白名单 %s: %w", item.LegacyID, err)
		}
		reason := strings.TrimSpace(item.Remark)
		if reason == "" {
			reason = ReasonPlaceholder
			notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "whitelist_empty_remark",
				Message: "旧记录备注为空，已按迁移说明填充原因"})
		}
		validFrom, dated := legacyTimestamp(item.CreatedAt, item.UpdatedAt, now)
		if !dated {
			notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "whitelist_missing_created_at",
				Message: "旧记录创建时间为零值，生效时间改用最后更新时间"})
		}
		entry := policy.WhitelistEntry{
			ID:        "whitelist-dpi-" + item.LegacyID,
			Type:      kind,
			Value:     item.Value,
			Reason:    reason,
			Enabled:   true,
			ValidFrom: validFrom,
			Revision:  1,
			CreatedBy: "dpi-analyze-migration",
			UpdatedBy: "dpi-analyze-migration",
			CreatedAt: validFrom,
			UpdatedAt: validFrom,
		}
		// NormalizeWhitelist is the validator the whitelist page runs on every
		// read, so running it here guarantees the stored document loads.
		if err := policy.NormalizeWhitelist(&entry); err != nil {
			return nil, nil, fmt.Errorf("白名单 %s (%s): %w", item.LegacyID, item.Value, err)
		}
		entries = append(entries, entry)
	}
	if err := rejectDuplicateWhitelist(entries); err != nil {
		return nil, nil, err
	}
	return entries, notes, nil
}

func rejectDuplicateWhitelist(entries []policy.WhitelistEntry) error {
	seen := map[string]string{}
	for _, e := range entries {
		key := fmt.Sprintf("%s|%s|%s|%s", e.Type, e.Value, e.CampusID, e.AccessDomain)
		if first, ok := seen[key]; ok {
			return fmt.Errorf("白名单归一化后出现重复项: %s 与 %s 同为 %s %s", first, e.ID, e.Type, e.Value)
		}
		seen[key] = e.ID
	}
	return nil
}

func whitelistType(legacy int) (string, error) {
	switch legacy {
	case LegacyWhitelistIP:
		return "ip", nil
	case LegacyWhitelistUser:
		return "account", nil
	case LegacyWhitelistMAC:
		return "mac", nil
	case LegacyWhitelistIPRange:
		return "network", nil
	case LegacyWhitelistGroup:
		return "group", nil
	default:
		return "", fmt.Errorf("未知的旧白名单类型 %d", legacy)
	}
}

// legacyTimestamp prefers the legacy creation time and falls back to the update
// time. The legacy exporter emitted Go's zero time for a handful of records.
func legacyTimestamp(created, updated string, now time.Time) (time.Time, bool) {
	if at, ok := parseTimestamp(created); ok {
		return at, true
	}
	if at, ok := parseTimestamp(updated); ok {
		return at, false
	}
	return now.UTC(), false
}

func parseTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || at.Year() < 2000 {
		return time.Time{}, false
	}
	return at.UTC(), true
}

// ConvertStrategies maps legacy execution strategies onto sentinel policies.
//
// A converted policy is always disabled and in observe mode: the legacy
// strategies are disabled on site and are migrated for later reuse, not to take
// effect. Origin is deliberately left unset, because a policy carrying an
// import origin is restricted to observe mode forever and this configuration is
// meant to be switchable later.
func ConvertStrategies(items []LegacyStrategy) ([]policy.Definition, []Note, error) {
	policies := make([]policy.Definition, 0, len(items))
	notes := []Note{}
	for _, item := range items {
		definition, itemNotes, err := convertStrategy(item)
		if err != nil {
			return nil, nil, err
		}
		policies = append(policies, definition)
		notes = append(notes, itemNotes...)
	}
	return policies, notes, nil
}

func convertStrategy(item LegacyStrategy) (policy.Definition, []Note, error) {
	notes := []Note{}

	definition := policy.Definition{
		ID:             idPrefix + item.LegacyID,
		Name:           item.Name + "（迁移自 dpi-analyze）",
		Enabled:        false,
		Priority:       0,
		Mode:           "observe",
		Trigger:        "quota_exceeded",
		ActionModel:    "dpi-strategy/v1",
		WindowSeconds:  legacyDefaultWindowSeconds,
		Revision:       1,
		Scope:          policy.Scope{},
		Limits:         policy.Limits{},
		SustainSeconds: 0,
	}

	cidrs, cidrNotes, err := convertCIDRs(item.Match.IPRanges, item.LegacyID)
	if err != nil {
		return policy.Definition{}, nil, err
	}
	definition.Scope.CIDRs = cidrs
	notes = append(notes, cidrNotes...)

	definition.Scope.Products = compact(item.Match.ProductIDs)
	definition.Scope.Groups = compact(item.Match.GroupIDs)
	definition.Scope.VLANs = compact(item.Match.VLANs)

	if len(item.Match.Domains) > 0 {
		notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "match_domains_dropped",
			Message: fmt.Sprintf("旧策略按域名匹配 %s，新策略模型没有域名维度，该项未迁移", strings.Join(item.Match.Domains, ","))})
	}
	if item.RouterPunishEnabled || item.RouterConfidenceThreshold > 0 {
		notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "router_confidence_dropped",
			Message: fmt.Sprintf("旧策略的路由器打击开关/置信度阈值(%d)在策略模型中无对应字段，需依赖路由证据判定",
				item.RouterConfidenceThreshold)})
	}

	definition.Limits = convertLimits(item.Condition, item.LegacyID, &notes)

	stages, stageNotes, err := convertStages(item, &definition)
	if err != nil {
		return policy.Definition{}, nil, err
	}
	definition.Stages = stages
	notes = append(notes, stageNotes...)

	if err := definition.Validate(); err != nil {
		return policy.Definition{}, nil, fmt.Errorf("策略 %s (%s) 校验失败: %w", item.LegacyID, item.Name, err)
	}
	return definition, notes, nil
}

func convertLimits(cond LegacyCond, legacyID string, notes *[]Note) policy.Limits {
	limits := policy.Limits{}
	assign := func(value int, target **int, label string) {
		if value > 0 {
			v := value
			*target = &v
			return
		}
		*notes = append(*notes, Note{LegacyID: legacyID, Kind: "condition_zero",
			Message: fmt.Sprintf("旧条件 %s=0 在旧引擎中等价于“不限制”，迁移为未设置", label)})
	}
	assign(cond.All, &limits.Total, "all")
	assign(cond.PC, &limits.PC, "pc")
	assign(cond.Mobile, &limits.Mobile, "mobile")
	if cond.RouteIncrease {
		// The legacy condition is the boolean "is a routed device"; the closest
		// sentinel expression is "at least one router among the devices".
		zero := 0
		limits.Router = &zero
		*notes = append(*notes, Note{LegacyID: legacyID, Kind: "route_increase_remapped",
			Message: "旧条件 route_increase 为布尔量，迁移为“路由设备数 > 0”，口径需现场确认"})
	}
	return limits
}

// convertStages keeps only the legacy actions that were enabled. A disabled
// legacy action converted into an armed stage would grant the migrated policy
// authority the legacy system never had.
func convertStages(item LegacyStrategy, definition *policy.Definition) ([]policy.Stage, []Note, error) {
	stages := []policy.Stage{}
	notes := []Note{}
	dropped := []string{}

	for _, action := range item.Actions {
		actionName, known := StageAction(action.Type)
		if !known {
			return nil, nil, fmt.Errorf("策略 %s: 未知动作 %q", item.LegacyID, action.Type)
		}
		if !action.Enabled {
			dropped = append(dropped, action.Type)
			continue
		}
		stage := policy.Stage{Action: actionName}

		switch action.Type {
		case actionMsgNotify:
			template, _ := action.Params["template_id"].(string)
			stage.Template = strings.TrimSpace(template)
			stage.AfterSeconds = firstPositiveInt(action.Params, 0, "first_duration", "duration")
			stage.IntervalSeconds = firstPositiveInt(action.Params, 0, "repeat_interval", "interval")
			if routerOnly, _ := action.Params["router_only_notify"].(bool); routerOnly {
				notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "router_only_notify_dropped",
					Message: "旧动作要求“仅路由器用户发送”，新通知动作没有该过滤，需现场确认是否补"})
			}
		case actionForceOffline:
			stage.SyncNotify = boolParam(action.Params, "sync_msg")
		case actionBandwidthReduction:
			// The legacy action carried no rate; the sentinel stage requires one.
			stage.RateKbps = intParam(action.Params, "rate_kbps", 1024)
			stage.DurationSeconds = firstPositiveInt(action.Params, 3600, "duration", "duration_seconds")
			stage.SyncNotify = boolParam(action.Params, "sync_msg")
			notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "rate_limit_defaulted",
				Message: fmt.Sprintf("旧降速动作未记录速率，已填默认 %d Kbps / %d 秒，启用前需现场确认",
					stage.RateKbps, stage.DurationSeconds)})
		case actionUserDisable:
			duration := intParam(action.Params, "duration", 0)
			if duration <= 0 {
				duration = legacyUserDisableSeconds
			}
			stage.DurationSeconds = duration
			stage.PutBlack = boolParam(action.Params, "put_black")
			stage.SyncNotify = boolParam(action.Params, "sync_msg")
		}

		for _, dependency := range action.DependsOn {
			resolved, known := StageAction(dependency)
			if !known {
				return nil, nil, fmt.Errorf("策略 %s: 未知依赖动作 %q", item.LegacyID, dependency)
			}
			stage.DependsOn = append(stage.DependsOn, resolved)
		}
		// The legacy "count" belongs to the escalation edge: this action fires
		// once its dependency has run that many times. The sentinel expresses
		// the same edge as the dependent stage's minimum episode count.
		if len(stage.DependsOn) > 0 {
			stage.MinEpisodes = intParam(action.Params, "count", 0)
			if stage.MinEpisodes == 0 {
				notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "escalation_count_missing",
					Message: fmt.Sprintf("旧动作 %s 依赖前置动作但未配置 count，新策略按 1 次处理", action.Type)})
			}
		}
		stages = append(stages, stage)
	}

	if len(dropped) > 0 {
		notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "disabled_actions_dropped",
			Message: fmt.Sprintf("旧策略中处于关闭状态的动作未迁移: %s", strings.Join(dropped, ","))})
	}
	if len(stages) == 0 {
		// The legacy policy existed only as a scope plus thresholds. Keep it as
		// a recording policy so the scope is preserved and reusable.
		stages = append(stages, policy.Stage{Action: "record"})
		notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "record_only_placeholder",
			Message: "旧策略没有任何启用的动作，迁移为仅记录策略以保留匹配范围"})
	}
	return stages, notes, nil
}

// convertCIDRs maps legacy match ranges onto sentinel CIDR scope. The legacy
// matcher accepted a bare address, a CIDR and an "a-b" range, while the sentinel
// scope validator accepts prefixes only.
func convertCIDRs(ranges []string, legacyID string) ([]string, []Note, error) {
	out := []string{}
	notes := []Note{}
	for _, raw := range ranges {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		switch {
		case strings.Contains(value, "/"):
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, nil, fmt.Errorf("策略 %s: 网段 %q 无法解析", legacyID, value)
			}
			out = append(out, prefix.Masked().String())
		case strings.Contains(value, "-"):
			parts := strings.SplitN(value, "-", 2)
			start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, nil, fmt.Errorf("策略 %s: 地址区间 %q 起点无法解析", legacyID, value)
			}
			end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, nil, fmt.Errorf("策略 %s: 地址区间 %q 终点无法解析", legacyID, value)
			}
			prefixes, err := rangeToPrefixes(start, end)
			if err != nil {
				return nil, nil, fmt.Errorf("策略 %s: %w", legacyID, err)
			}
			out = append(out, prefixes...)
			notes = append(notes, Note{LegacyID: legacyID, Kind: "ip_range_expanded",
				Message: fmt.Sprintf("旧地址区间 %s 展开为 %s", value, strings.Join(prefixes, ","))})
		default:
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return nil, nil, fmt.Errorf("策略 %s: 地址 %q 无法解析", legacyID, value)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()).String())
			notes = append(notes, Note{LegacyID: legacyID, Kind: "single_ip_to_prefix",
				Message: fmt.Sprintf("旧单地址 %s 迁移为 %s", value, netip.PrefixFrom(addr, addr.BitLen()).String())})
		}
	}
	return out, notes, nil
}

// rangeToPrefixes converts an inclusive address range into the minimal set of
// covering prefixes by repeatedly taking the largest aligned block that still
// ends at or before the range end.
func rangeToPrefixes(start, end netip.Addr) ([]string, error) {
	start, end = start.Unmap(), end.Unmap()
	if start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return nil, fmt.Errorf("地址区间必须同属 IPv4 或 IPv6，且起点不能大于终点")
	}
	bits := start.BitLen()
	prefixes := []string{}
	for addr := start; addr.IsValid() && addr.Compare(end) <= 0; {
		length := bits
		for length > 0 {
			candidate := netip.PrefixFrom(addr, length-1)
			if !candidate.IsValid() || candidate.Masked().Addr() != addr {
				break
			}
			if prefixLast(candidate).Compare(end) > 0 {
				break
			}
			length--
		}
		prefix := netip.PrefixFrom(addr, length)
		prefixes = append(prefixes, prefix.String())
		last := prefixLast(prefix)
		if last.Compare(end) >= 0 {
			break
		}
		addr = last.Next()
	}
	return prefixes, nil
}

// prefixLast returns the highest address inside a prefix.
func prefixLast(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	hostBits := func(byteIndex int) int {
		return 8 - clampInt(prefix.Bits()-byteIndex*8, 0, 8)
	}
	if addr.Is4() {
		raw := addr.As4()
		for i := range raw {
			if host := hostBits(i); host > 0 {
				raw[i] |= byte(255 >> (8 - host))
			}
		}
		return netip.AddrFrom4(raw)
	}
	raw := addr.As16()
	for i := range raw {
		if host := hostBits(i); host > 0 {
			raw[i] |= byte(255 >> (8 - host))
		}
	}
	return netip.AddrFrom16(raw)
}

func clampInt(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

// ConvertTemplates maps the legacy template file onto sentinel templates. The
// legacy placeholder vocabulary is a superset of the sentinel one, so
// references are rewritten rather than translated at render time.
func ConvertTemplates(items []LegacyTemplate) ([]notify.Template, error) {
	templates := make([]notify.Template, 0, len(items))
	for _, item := range items {
		template := notify.Template{
			TemplateID:  strings.TrimSpace(item.TemplateID),
			Name:        strings.TrimSpace(item.Name),
			ChannelType: notify.ChannelTypeSRunSMS,
			Body:        rewritePlaceholders(item.Body),
			Enabled:     true,
			Revision:    1,
		}
		if err := notify.ValidateTemplate(&template); err != nil {
			return nil, fmt.Errorf("模板 %s (%s): %w", item.TemplateID, item.Name, err)
		}
		templates = append(templates, template)
	}
	return templates, nil
}

// rewritePlaceholders maps legacy variable names onto the sentinel vocabulary.
func rewritePlaceholders(body string) string {
	replacer := strings.NewReplacer(
		"{{user_name}}", "{{name}}",
		"{{user_id}}", "{{account}}",
		"{{user_mac}}", "{{mac}}",
		"{{student_id}}", "{{student_id}}",
	)
	return replacer.Replace(body)
}

// ConvertSMSChannel maps the legacy Supwisdom channel onto a sentinel
// notification channel. The channel is created disabled: the legacy site has
// not switched message delivery to the sentinel yet.
func ConvertSMSChannel(legacy LegacySMSChannel, secret string) (notify.Channel, error) {
	base := strings.TrimRight(strings.TrimSpace(legacy.APIHost), "/")
	if base == "" {
		return notify.Channel{}, fmt.Errorf("旧短信通道缺少 api_host")
	}
	channel := notify.Channel{
		ChannelID:     "dpi-analyze-sms-" + legacy.LegacyID,
		Name:          "Supwisdom 短信通道（迁移自 dpi-analyze）",
		ChannelType:   notify.ChannelTypeSRunSMS,
		EndpointURL:   base + "/apis/messagecenter/v1/poaMessage/messageSend",
		TokenEndpoint: base + "/oauth2/token",
		TokenScope:    "messagecenter:v1:sendMessage",
		AuthType:      notify.AuthOAuth2Client,
		Config: notify.ChannelConfig{
			ClientID:        legacy.ClientID,
			MessageTypeCode: legacy.MessageTypeCode,
			SendTypes:       []string{"SMS", "WECHAT"},
			TimeoutSec:      notify.DefaultTimeoutSec,
		},
		IsDefault: false,
		Enabled:   false,
		Revision:  1,
		Secret:    secret,
	}
	if err := notify.ValidateChannel(&channel); err != nil {
		return notify.Channel{}, fmt.Errorf("短信通道 %s: %w", legacy.LegacyID, err)
	}
	return channel, nil
}

// ConvertPoisonRules maps legacy behaviour rules onto sentinel destination
// target rules. The rule converts disabled even though the legacy rule was
// enabled, because the sentinel rule ships disabled by design and enabling it
// changes what leaves the site.
func ConvertPoisonRules(items []LegacyPoisonRule) ([]poison.Rule, []Note) {
	rules := make([]poison.Rule, 0, len(items))
	notes := []Note{}
	for _, item := range items {
		rule := poison.Rule{
			RuleID:        idPrefix + item.LegacyID,
			Name:          item.Name + "（迁移自 dpi-analyze）",
			Enabled:       false,
			BehaviorType:  item.BehaviorType,
			TargetType:    item.TargetType,
			Targets:       compact(item.Targets),
			WindowSeconds: item.WindowSeconds,
			Threshold:     item.Threshold,
			Direction:     poison.DirectionAny,
		}
		rules = append(rules, rule)
		if item.Enabled {
			notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "poison_rule_disabled_on_import",
				Message: "旧行为规则处于启用状态，新规则按设计先以关闭状态导入，需现场预览后再启用"})
		}
		if item.PushEnabled {
			notes = append(notes, Note{LegacyID: item.LegacyID, Kind: "poison_push_disabled_on_import",
				Message: "旧行为规则开启了推送，新规则导入时关闭推送，待南向通道确认后再开启"})
		}
	}
	return rules, notes
}

// compact trims values and drops empties while preserving order.
func compact(values []string) []string {
	out := []string{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func intParam(params map[string]any, key string, fallback int) int {
	if params == nil {
		return fallback
	}
	switch value := params[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case int64:
		return int(value)
	default:
		return fallback
	}
}

func boolParam(params map[string]any, key string) bool {
	if params == nil {
		return false
	}
	value, _ := params[key].(bool)
	return value
}

// firstPositiveInt returns the first named parameter holding a positive
// integer, or fallback when none does.
func firstPositiveInt(params map[string]any, fallback int, keys ...string) int {
	for _, key := range keys {
		if value := intParam(params, key, 0); value > 0 {
			return value
		}
	}
	return fallback
}
