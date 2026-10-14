package controlplane

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/legacydpi"
	"proxy-sentinel/internal/notify"
	"proxy-sentinel/internal/policy"
)

// TestEmitLegacyDPIMigrationSQL renders the dpi-analyze configuration fixture
// into an idempotent SQL script. It is the apply step for the migration and is
// skipped unless an output path is supplied.
//
// The SMS client secret and the action master key are read from the environment
// so that neither ever appears in the repository or in a test log. Only the
// sealed ciphertext is written to the script.
//
//	LEGACY_DPI_EMIT_SQL=/tmp/legacy-dpi.sql \
//	PROXY_SENTINEL_ACTION_MASTER_KEY=... \
//	LEGACY_DPI_SMS_CLIENT_SECRET=... \
//	go test ./internal/controlplane -run TestEmitLegacyDPIMigrationSQL
func TestEmitLegacyDPIMigrationSQL(t *testing.T) {
	out := strings.TrimSpace(os.Getenv("LEGACY_DPI_EMIT_SQL"))
	if out == "" {
		t.Skip("设置 LEGACY_DPI_EMIT_SQL 以生成迁移 SQL")
	}
	masterKey := os.Getenv("PROXY_SENTINEL_ACTION_MASTER_KEY")
	if len(masterKey) < 16 {
		t.Fatal("PROXY_SENTINEL_ACTION_MASTER_KEY 缺失或过短，无法密封通道密钥")
	}
	secret := os.Getenv("LEGACY_DPI_SMS_CLIENT_SECRET")
	if strings.TrimSpace(secret) == "" {
		t.Fatal("LEGACY_DPI_SMS_CLIENT_SECRET 缺失，无法迁移短信通道凭据")
	}

	cfg, err := legacydpi.LoadConfig(filepath.Join("..", "legacydpi", "testdata", "legacy-dpi-config.json"))
	if err != nil {
		t.Fatalf("加载 legacy fixture 失败: %v", err)
	}
	// Anchor the conversion to the export time so repeated runs produce an
	// identical script that can be reviewed as a diff.
	anchor := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, cfg.ExportedAt); err == nil {
		anchor = parsed.UTC()
	}

	result, err := legacydpi.Convert(cfg, secret, anchor)
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}

	// Seal with the production function so the stored value is exactly what the
	// notification sender will decrypt at delivery time.
	sealer := &Server{actionMasterKey: []byte(masterKey)}
	sealed, err := sealer.encryptConnectorSecret(result.Channel.Secret)
	if err != nil {
		t.Fatalf("密封通道密钥失败: %v", err)
	}
	result.Channel.EncryptedSecret = sealed
	result.Channel.Secret = ""

	script, err := renderLegacyDPIScript(cfg, result, anchor)
	if err != nil {
		t.Fatalf("渲染 SQL 失败: %v", err)
	}
	if err := os.WriteFile(out, []byte(script), 0o600); err != nil {
		t.Fatalf("写入 SQL 失败: %v", err)
	}
	t.Logf("已生成 %s (%d 字节): 白名单 %d 条, 策略 %d 条, 模板 %d 个, 通道 %d 个, 行为规则 %d 条",
		out, len(script), len(result.Whitelist), len(result.Policies), len(result.Templates), 1, len(result.Rules))
}

const (
	legacyMigrationActor          = "dpi-analyze-migration"
	legacyWhitelistSettingKey     = "policy_whitelist_v1"
	dollarQuoteTag                = "$legacydpi$"
	legacyMigrationAuditActionFmt = "policy.migration.dpi_analyze.%s"
)

func renderLegacyDPIScript(cfg legacydpi.Config, result legacydpi.Result, now time.Time) (string, error) {
	var b strings.Builder

	b.WriteString("-- dpi-analyze -> proxy-sentinel 配置迁移\n")
	b.WriteString("-- 生成器: internal/controlplane/legacydpi_emit_test.go\n")
	b.WriteString("-- 转换版本: " + legacydpi.ConversionVersion + "\n")
	b.WriteString("-- 来源: " + comment(cfg.Source) + "\n")
	b.WriteString("-- 导出时间: " + cfg.ExportedAt + "\n")
	b.WriteString("-- 生成时间: " + now.Format(time.RFC3339) + "\n")
	b.WriteString("--\n")
	b.WriteString("-- 幂等: 全部语句使用 upsert，可重复执行。\n")
	b.WriteString("-- 安全性: 默认关闭。策略为 disabled + observe，短信通道与行为规则均不启用。\n")
	if len(result.Notes) > 0 {
		b.WriteString("--\n-- 转换说明（旧系统语义与新模型不一致处）:\n")
		for _, note := range result.Notes {
			b.WriteString("--   [" + note.Kind + "] " + comment(note.Message) + "\n")
		}
	}
	b.WriteString("\nBEGIN;\n\n")

	// 1. Whitelist: one JSON document in control_plane_settings.
	document, err := json.Marshal(whitelistDocument{Entries: result.Whitelist})
	if err != nil {
		return "", err
	}
	b.WriteString("-- 1. 白名单 (" + fmt.Sprint(len(result.Whitelist)) + " 条)\n")
	b.WriteString("INSERT INTO control_plane_settings(setting_key,setting_value) VALUES (")
	b.WriteString(quote(legacyWhitelistSettingKey) + ", " + dollarQuote(string(document)) + "::jsonb)")
	b.WriteString(" ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, updated_at=now();\n\n")

	// 2. Policies.
	b.WriteString("-- 2. 防代理执行策略 (" + fmt.Sprint(len(result.Policies)) + " 条, 全部 disabled + observe)\n")
	for _, p := range result.Policies {
		raw, err := json.Marshal(p)
		if err != nil {
			return "", err
		}
		b.WriteString("INSERT INTO account_policy_definitions(id,document,updated_at) VALUES (")
		b.WriteString(quote(p.ID) + ", " + dollarQuote(string(raw)) + "::jsonb, now())")
		b.WriteString(" ON CONFLICT(id) DO UPDATE SET document=excluded.document, updated_at=now();\n")
	}
	b.WriteString("\n")

	// 3. Notification templates.
	b.WriteString("-- 3. 通知模板 (" + fmt.Sprint(len(result.Templates)) + " 个, 保留旧 template_id 以便策略引用)\n")
	for _, tpl := range result.Templates {
		variables, err := json.Marshal(tpl.Variables)
		if err != nil {
			return "", err
		}
		b.WriteString("INSERT INTO notification_templates(template_id,name,channel_type,subject,body,variables,enabled,revision,created_by,updated_by) VALUES (")
		b.WriteString(strings.Join([]string{
			quote(tpl.TemplateID),
			quote(tpl.Name),
			quote(tpl.ChannelType),
			quote(tpl.Subject),
			dollarQuote(tpl.Body),
			dollarQuote(string(variables)) + "::jsonb",
			sqlBool(tpl.Enabled),
			"1",
			quote(legacyMigrationActor),
			quote(legacyMigrationActor),
		}, ", "))
		b.WriteString(") ON CONFLICT(template_id) DO UPDATE SET name=excluded.name, channel_type=excluded.channel_type, subject=excluded.subject, body=excluded.body, variables=excluded.variables, enabled=excluded.enabled, revision=notification_templates.revision+1, updated_by=excluded.updated_by, updated_at=now();\n")
	}
	b.WriteString("\n")

	// 4. Notification channel, sealed and disabled.
	channel := result.Channel
	config, err := json.Marshal(channel.Config)
	if err != nil {
		return "", err
	}
	b.WriteString("-- 4. 短信通道 (1 个, 关闭; 密钥已用 action master key 密封)\n")
	b.WriteString("INSERT INTO notification_channels(channel_id,name,channel_type,endpoint_url,token_endpoint,token_scope,auth_type,encrypted_secret,config,is_default,enabled,revision,created_by,updated_by) VALUES (")
	b.WriteString(strings.Join([]string{
		quote(channel.ChannelID),
		quote(channel.Name),
		quote(channel.ChannelType),
		quote(channel.EndpointURL),
		quote(channel.TokenEndpoint),
		quote(channel.TokenScope),
		quote(channel.AuthType),
		quote(channel.EncryptedSecret),
		dollarQuote(string(config)) + "::jsonb",
		sqlBool(false),
		sqlBool(false),
		"1",
		quote(legacyMigrationActor),
		quote(legacyMigrationActor),
	}, ", "))
	b.WriteString(") ON CONFLICT(channel_id) DO UPDATE SET name=excluded.name, channel_type=excluded.channel_type, endpoint_url=excluded.endpoint_url, token_endpoint=excluded.token_endpoint, token_scope=excluded.token_scope, auth_type=excluded.auth_type, encrypted_secret=excluded.encrypted_secret, config=excluded.config, enabled=excluded.enabled, revision=notification_channels.revision+1, updated_by=excluded.updated_by, updated_at=now();\n\n")

	// 5. Destination target rules, disabled.
	b.WriteString("-- 5. 投毒行为规则 (" + fmt.Sprint(len(result.Rules)) + " 条, 关闭且不推送)\n")
	for _, rule := range result.Rules {
		b.WriteString("INSERT INTO destination_target_rules(rule_id,name,enabled,behavior_type,target_type,targets,window_seconds,threshold,direction,push_enabled,push_without_account,created_by,updated_by) VALUES (")
		b.WriteString(strings.Join([]string{
			quote(rule.RuleID),
			quote(rule.Name),
			sqlBool(false),
			quote(rule.BehaviorType),
			quote(rule.TargetType),
			textArray(rule.Targets),
			fmt.Sprint(rule.WindowSeconds),
			fmt.Sprint(rule.Threshold),
			quote(rule.Direction),
			sqlBool(false),
			sqlBool(false),
			quote(legacyMigrationActor),
			quote(legacyMigrationActor),
		}, ", "))
		b.WriteString(") ON CONFLICT(rule_id) DO UPDATE SET name=excluded.name, behavior_type=excluded.behavior_type, target_type=excluded.target_type, targets=excluded.targets, window_seconds=excluded.window_seconds, threshold=excluded.threshold, direction=excluded.direction, updated_by=excluded.updated_by, updated_at=now();\n")
	}
	b.WriteString("\n")

	// 6. Audit trail: the migration must be attributable like any other change.
	b.WriteString("-- 6. 审计记录\n")
	auditRows := []struct {
		suffix string
		target string
		count  int
	}{
		{"whitelist", legacyWhitelistSettingKey, len(result.Whitelist)},
		{"policies", "account_policy_definitions", len(result.Policies)},
		{"templates", "notification_templates", len(result.Templates)},
		{"channels", channel.ChannelID, 1},
		{"destination_rules", "destination_target_rules", len(result.Rules)},
	}
	for _, row := range auditRows {
		outcome, err := json.Marshal(map[string]any{
			"conversion_version": legacydpi.ConversionVersion,
			"source":             cfg.Source,
			"exported_at":        cfg.ExportedAt,
			"actor":              legacyMigrationActor,
			"count":              row.count,
		})
		if err != nil {
			return "", err
		}
		b.WriteString("INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES (")
		b.WriteString(strings.Join([]string{
			quote("audit-dpi-migration-" + row.suffix),
			quote(legacyMigrationActor),
			quote(fmt.Sprintf(legacyMigrationAuditActionFmt, row.suffix)),
			quote(row.target),
			dollarQuote(string(outcome)),
			"now()",
		}, ", "))
		b.WriteString(") ON CONFLICT(audit_id) DO NOTHING;\n")
	}

	b.WriteString("\nCOMMIT;\n")
	return b.String(), nil
}

// quote renders a SQL string literal.
func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// dollarQuote renders a SQL literal that may contain quotes, newlines and JSON.
func dollarQuote(value string) string {
	return dollarQuoteTag + value + dollarQuoteTag
}

func sqlBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func textArray(values []string) string {
	if len(values) == 0 {
		return "ARRAY[]::text[]"
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, quote(value))
	}
	return "ARRAY[" + strings.Join(quoted, ",") + "]::text[]"
}

// comment strips characters that would terminate a SQL line comment.
func comment(value string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(value)
}

// The emitter must never store an unsealed secret.
func TestEmittedScriptSealsChannelSecret(t *testing.T) {
	cfg, err := legacydpi.LoadConfig(filepath.Join("..", "legacydpi", "testdata", "legacy-dpi-config.json"))
	if err != nil {
		t.Fatalf("加载 fixture 失败: %v", err)
	}
	const plaintext = "plain-secret-must-not-appear"
	result, err := legacydpi.Convert(cfg, plaintext, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	sealer := &Server{actionMasterKey: []byte("unit-test-master-key-0123456789")}
	sealed, err := sealer.encryptConnectorSecret(result.Channel.Secret)
	if err != nil {
		t.Fatalf("密封失败: %v", err)
	}
	result.Channel.EncryptedSecret = sealed
	result.Channel.Secret = ""

	script, err := renderLegacyDPIScript(cfg, result, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	if strings.Contains(script, plaintext) {
		t.Fatal("生成的脚本包含明文密钥")
	}
	if !strings.Contains(script, sealed) {
		t.Fatal("生成的脚本缺少密封后的密钥")
	}
	// The sender must be able to decrypt what the emitter sealed.
	recovered, err := sealer.decryptConnectorSecret(sealed)
	if err != nil || recovered != plaintext {
		t.Fatalf("密封结果无法被投递路径解开: %v", err)
	}
}

// The migration must not silently arm anything on the target system.
func TestEmittedScriptEnablesNothing(t *testing.T) {
	cfg, err := legacydpi.LoadConfig(filepath.Join("..", "legacydpi", "testdata", "legacy-dpi-config.json"))
	if err != nil {
		t.Fatalf("加载 fixture 失败: %v", err)
	}
	result, err := legacydpi.Convert(cfg, "secret", time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	for _, p := range result.Policies {
		if p.Enabled {
			t.Fatalf("策略 %s 为启用状态", p.ID)
		}
	}
	if result.Channel.Enabled {
		t.Fatal("短信通道为启用状态")
	}
	for _, rule := range result.Rules {
		if rule.Enabled {
			t.Fatalf("行为规则 %s 为启用状态", rule.RuleID)
		}
	}
}

// Policy documents must survive the JSON round trip the read path performs.
func TestEmittedPolicyDocumentsUnmarshal(t *testing.T) {
	cfg, err := legacydpi.LoadConfig(filepath.Join("..", "legacydpi", "testdata", "legacy-dpi-config.json"))
	if err != nil {
		t.Fatalf("加载 fixture 失败: %v", err)
	}
	result, err := legacydpi.Convert(cfg, "secret", time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	for _, p := range result.Policies {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("序列化策略 %s 失败: %v", p.ID, err)
		}
		var decoded policy.Definition
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("策略 %s 无法被读取路径解析: %v", p.ID, err)
		}
		if decoded.ID != p.ID || decoded.ActionModel != "dpi-strategy/v1" {
			t.Fatalf("策略 %s 往返后字段丢失: %+v", p.ID, decoded)
		}
	}
	for _, tpl := range result.Templates {
		if err := notify.ValidateTemplate(&tpl); err != nil {
			t.Fatalf("模板 %s 无法被投递路径使用: %v", tpl.TemplateID, err)
		}
	}
}
