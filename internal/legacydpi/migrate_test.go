package legacydpi

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/notify"
	"proxy-sentinel/internal/policy"
)

var fixtureTime = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)

func loadFixture(t *testing.T) Config {
	t.Helper()
	cfg, err := LoadConfig(filepath.Join("testdata", "legacy-dpi-config.json"))
	if err != nil {
		t.Fatalf("加载 fixture 失败: %v", err)
	}
	return cfg
}

func convertFixture(t *testing.T) Result {
	t.Helper()
	result, err := Convert(loadFixture(t), "test-client-secret", fixtureTime)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	return result
}

func TestConvertProducesEveryLegacyEntity(t *testing.T) {
	result := convertFixture(t)

	if got := len(result.Whitelist); got != 18 {
		t.Fatalf("白名单条数 = %d, 期望 18", got)
	}
	if got := len(result.Policies); got != 3 {
		t.Fatalf("策略条数 = %d, 期望 3", got)
	}
	if got := len(result.Templates); got != 7 {
		t.Fatalf("模板条数 = %d, 期望 7", got)
	}
	if got := len(result.Rules); got != 1 {
		t.Fatalf("行为规则条数 = %d, 期望 1", got)
	}
	if result.Channel.ChannelID == "" {
		t.Fatal("短信通道未生成")
	}
}

// The whitelist page normalizes every stored entry on read, so a single entry
// that fails normalization would break the whole list.
func TestConvertedWhitelistPassesReadNormalization(t *testing.T) {
	result := convertFixture(t)
	byType := map[string]int{}
	for _, entry := range result.Whitelist {
		copy := entry
		if err := policy.NormalizeWhitelist(&copy); err != nil {
			t.Fatalf("白名单 %s (%s) 未通过读取校验: %v", entry.ID, entry.Value, err)
		}
		if copy.Value != entry.Value {
			t.Fatalf("白名单 %s 存储值 %q 不是归一化结果 %q", entry.ID, entry.Value, copy.Value)
		}
		if !copy.Active(fixtureTime) {
			t.Fatalf("白名单 %s 在迁移时刻不生效", entry.ID)
		}
		byType[entry.Type]++
	}
	want := map[string]int{"account": 6, "mac": 8, "network": 4}
	for kind, count := range want {
		if byType[kind] != count {
			t.Fatalf("白名单类型 %s 条数 = %d, 期望 %d", kind, byType[kind], count)
		}
	}
}

// The legacy matcher compared MAC strings byte-for-byte, so this migration is
// also a correctness fix; the stored value must be the normalized form.
func TestConvertedWhitelistNormalizesLegacyValues(t *testing.T) {
	result := convertFixture(t)
	values := map[string]string{}
	reasons := map[string]string{}
	for _, entry := range result.Whitelist {
		values[entry.ID] = entry.Value
		reasons[entry.ID] = entry.Reason
	}

	if got := values["whitelist-dpi-6a8ffa67185d4541d7772f8f"]; got != "b8:f8:83:36:b7:8d" {
		t.Fatalf("MAC 未归一化: %q", got)
	}
	if got := values["whitelist-dpi-6a55e2067b9e98c00e9df957"]; got != "067911" {
		t.Fatalf("账号未去除尾部空格: %q", got)
	}
	if got := values["whitelist-dpi-6a54451a7b9e98c00e9df947"]; got != "10.202.0.0/16" {
		t.Fatalf("网段被改写: %q", got)
	}

	emptyRemark := []string{
		"whitelist-dpi-6a5494877b9e98c00e9df953",
		"whitelist-dpi-6a62c6c3434b7ae2443f8127",
		"whitelist-dpi-6a62c6cd434b7ae2443f8129",
		"whitelist-dpi-6a7abef1185d4541d7772f87",
	}
	for _, id := range emptyRemark {
		if reasons[id] != ReasonPlaceholder {
			t.Fatalf("空备注条目 %s 的原因 = %q, 期望迁移说明", id, reasons[id])
		}
	}
}

// A legacy record whose created_at is Go's zero time must not become the
// entry's validity start.
func TestConvertedWhitelistIgnoresZeroLegacyTimestamps(t *testing.T) {
	result := convertFixture(t)
	for _, entry := range result.Whitelist {
		if entry.ValidFrom.Year() < 2000 {
			t.Fatalf("白名单 %s 生效时间为零值 %s", entry.ID, entry.ValidFrom)
		}
		if entry.Revision != 1 {
			t.Fatalf("白名单 %s 初始 revision = %d, 期望 1", entry.ID, entry.Revision)
		}
	}
}

// Migrated strategies must never be active: the legacy strategies were
// disabled on site and are imported for reuse, not to take effect.
func TestConvertedPoliciesAreDisabledAndObserveOnly(t *testing.T) {
	result := convertFixture(t)
	for _, p := range result.Policies {
		if p.Enabled {
			t.Fatalf("策略 %s 导入后处于启用状态", p.ID)
		}
		if p.Mode != "observe" {
			t.Fatalf("策略 %s 模式 = %q, 期望 observe", p.ID, p.Mode)
		}
		if p.Origin != nil {
			t.Fatalf("策略 %s 携带 origin 会被永久限制为 observe, 与后续复用目的冲突", p.ID)
		}
		if p.ActionModel != "dpi-strategy/v1" {
			t.Fatalf("策略 %s 动作模型 = %q", p.ID, p.ActionModel)
		}
	}
}

// The legacy route_increase flag has no exact equivalent; it converts to a
// router count floor and the difference is reported rather than hidden.
func TestConvertedPoliciesRemapConditions(t *testing.T) {
	result := convertFixture(t)
	byName := map[string]policy.Definition{}
	for _, p := range result.Policies {
		byName[p.ID] = p
	}

	test := byName["dpi-analyze:695f6ecde0abefbf341e40b3"]
	if got := test.Scope.CIDRs; len(got) != 1 || got[0] != "222.204.88.132/32" {
		t.Fatalf("单地址未转成 /32: %v", got)
	}
	if test.Limits.Total == nil || *test.Limits.Total != 3 {
		t.Fatalf("all=3 未映射到 Total: %v", test.Limits.Total)
	}
	if test.Limits.PC == nil || *test.Limits.PC != 2 {
		t.Fatalf("pc=2 未映射到 PC: %v", test.Limits.PC)
	}
	if test.Limits.Router == nil || *test.Limits.Router != 0 {
		t.Fatalf("route_increase 未映射为路由数下限: %v", test.Limits.Router)
	}
	if len(test.Stages) != 1 || test.Stages[0].Action != "notify" {
		t.Fatalf("仅启用 msg_notify 的策略动作 = %+v", test.Stages)
	}
	if test.Stages[0].AfterSeconds != 30 || test.Stages[0].IntervalSeconds != 300 {
		t.Fatalf("通知节奏未映射: %+v", test.Stages[0])
	}

	proxy := byName["dpi-analyze:6960678b2a913fef72363dcc"]
	if len(proxy.Scope.Products) != 28 {
		t.Fatalf("产品匹配数 = %d, 期望 28", len(proxy.Scope.Products))
	}
	if len(proxy.Stages) != 3 {
		t.Fatalf("代理行为策略动作数 = %d, 期望 3 (带宽降速在旧系统为关闭)", len(proxy.Stages))
	}
	if proxy.Stages[0].Action != "notify" || proxy.Stages[0].AfterSeconds != 172800 || proxy.Stages[0].IntervalSeconds != 86400 {
		t.Fatalf("首次通知节奏未映射: %+v", proxy.Stages[0])
	}
	if proxy.Stages[1].Action != "disconnect" || proxy.Stages[1].MinEpisodes != 2 || len(proxy.Stages[1].DependsOn) != 1 || proxy.Stages[1].DependsOn[0] != "notify" {
		t.Fatalf("下线升级语义未映射: %+v", proxy.Stages[1])
	}
	if proxy.Stages[2].Action != "disable_account" || proxy.Stages[2].MinEpisodes != 3 || proxy.Stages[2].DurationSeconds != legacyUserDisableSeconds {
		t.Fatalf("封禁升级语义未映射: %+v", proxy.Stages[2])
	}

	router := byName["dpi-analyze:69dd95717264cf975ae61db1"]
	if len(router.Stages) != 1 || router.Stages[0].Action != "record" {
		t.Fatalf("全部动作关闭的策略应迁移为仅记录: %+v", router.Stages)
	}
	if len(router.Scope.Products) != 1 || router.Scope.Products[0] != "86" {
		t.Fatalf("路由器策略产品范围 = %v", router.Scope.Products)
	}
}

func TestConvertedPoliciesPassProductionValidation(t *testing.T) {
	result := convertFixture(t)
	for _, p := range result.Policies {
		copy := p
		if err := copy.Validate(); err != nil {
			t.Fatalf("策略 %s 未通过生产校验: %v", p.ID, err)
		}
	}
}

// Every conversion decision that lost legacy intent must surface as a note.
func TestConversionReportsLostIntent(t *testing.T) {
	result := convertFixture(t)
	kinds := map[string]int{}
	for _, note := range result.Notes {
		kinds[note.Kind]++
	}
	for _, want := range []string{
		"whitelist_empty_remark",
		"whitelist_missing_created_at",
		"disabled_actions_dropped",
		"route_increase_remapped",
		"router_confidence_dropped",
		"single_ip_to_prefix",
		"record_only_placeholder",
		"router_only_notify_dropped",
		"poison_rule_disabled_on_import",
		"poison_push_disabled_on_import",
	} {
		if kinds[want] == 0 {
			t.Fatalf("缺少转换说明 %q; 实际: %v", want, kinds)
		}
	}
}

// The legacy placeholder vocabulary is not accepted by the sentinel renderer,
// so every template must be rewritten and validated.
func TestConvertedTemplatesUseSentinelVocabulary(t *testing.T) {
	result := convertFixture(t)
	for _, template := range result.Templates {
		if err := notify.ValidateTemplate(&template); err != nil {
			t.Fatalf("模板 %s 未通过校验: %v", template.TemplateID, err)
		}
		if strings.Contains(template.Body, "user_name") {
			t.Fatalf("模板 %s 仍引用旧变量: %q", template.TemplateID, template.Body)
		}
		if template.ChannelType != notify.ChannelTypeSRunSMS {
			t.Fatalf("模板 %s 通道类型 = %q", template.TemplateID, template.ChannelType)
		}
	}
}

// Strategy stages reference template ids, so the ids must survive the migration.
func TestTemplateReferencesResolve(t *testing.T) {
	result := convertFixture(t)
	known := map[string]bool{}
	for _, template := range result.Templates {
		known[template.TemplateID] = true
	}
	for _, p := range result.Policies {
		for _, stage := range p.Stages {
			if stage.Action != "notify" {
				continue
			}
			if !known[stage.Template] {
				t.Fatalf("策略 %s 引用了未迁移的模板 %q", p.ID, stage.Template)
			}
		}
	}
}

func TestConvertedSMSChannelIsDisabledAndPreservesEndpoint(t *testing.T) {
	result := convertFixture(t)
	channel := result.Channel
	if channel.Enabled || channel.IsDefault {
		t.Fatal("短信通道导入后必须是关闭且非默认")
	}
	if channel.ChannelType != notify.ChannelTypeSRunSMS || channel.AuthType != notify.AuthOAuth2Client {
		t.Fatalf("通道类型/鉴权 = %s/%s", channel.ChannelType, channel.AuthType)
	}
	if channel.EndpointURL != "https://poa.ncu.edu.cn/apis/messagecenter/v1/poaMessage/messageSend" {
		t.Fatalf("发送地址 = %q", channel.EndpointURL)
	}
	if channel.TokenEndpoint != "https://poa.ncu.edu.cn/oauth2/token" {
		t.Fatalf("token 地址 = %q", channel.TokenEndpoint)
	}
	if channel.TokenScope != "messagecenter:v1:sendMessage" {
		t.Fatalf("scope = %q", channel.TokenScope)
	}
	if channel.Config.MessageTypeCode != "MT1747384880000" || channel.Config.ClientID == "" {
		t.Fatalf("通道配置缺失: %+v", channel.Config)
	}
	if channel.Secret != "test-client-secret" {
		t.Fatal("客户端密钥未传给待密封字段")
	}
	if err := notify.ValidateChannel(&channel); err != nil {
		t.Fatalf("通道未通过校验: %v", err)
	}
}

func TestConvertedPoisonRuleIsDisabled(t *testing.T) {
	result := convertFixture(t)
	rule := result.Rules[0]
	if rule.Enabled {
		t.Fatal("行为规则导入后必须关闭")
	}
	if rule.BehaviorType != "high_frequency_internal" || rule.Threshold != 10000 || rule.WindowSeconds != 3600 {
		t.Fatalf("行为规则语义丢失: %+v", rule)
	}
	if rule.Direction != "any" {
		t.Fatalf("方向 = %q", rule.Direction)
	}
}

func TestRangeToPrefixesCoversRangeExactly(t *testing.T) {
	start := mustAddr(t, "10.0.0.5")
	end := mustAddr(t, "10.0.0.10")
	got, err := rangeToPrefixes(start, end)
	if err != nil {
		t.Fatalf("区间展开失败: %v", err)
	}
	want := []string{"10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/31", "10.0.0.10/32"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("区间展开 = %v, 期望 %v", got, want)
	}
}

func TestConvertRejectsUnknownLegacyShapes(t *testing.T) {
	cfg := loadFixture(t)
	cfg.Whitelist = append(cfg.Whitelist, LegacyWhitelist{LegacyID: "bad", Type: 99, Value: "x", Remark: "原因"})
	if _, err := Convert(cfg, "", fixtureTime); err == nil {
		t.Fatal("未知白名单类型应被拒绝")
	}

	cfg = loadFixture(t)
	cfg.Strategies[0].Actions[0].Type = "unknown_action"
	if _, err := Convert(cfg, "", fixtureTime); err == nil {
		t.Fatal("未知动作应被拒绝")
	}
}

func TestConvertRejectsWhitelistCollisionsAfterNormalization(t *testing.T) {
	cfg := Config{Whitelist: []LegacyWhitelist{
		{LegacyID: "a", Type: LegacyWhitelistMAC, Value: "00-5C-C2-C7-A2-07", Remark: "第一台"},
		{LegacyID: "b", Type: LegacyWhitelistMAC, Value: "00:5c:c2:c7:a2:07", Remark: "同一台"},
	}}
	if _, err := Convert(cfg, "", fixtureTime); err == nil {
		t.Fatal("归一化后重复的白名单必须被拒绝，否则页面读取会失败")
	}
}

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	parsed, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("地址 %q 解析失败: %v", raw, err)
	}
	return parsed
}
