# 旧系统能力补齐清单（南昌现场版，按优先级）

本文基于 `docs/legacy-feature-gap-ncu.md` 的对比结论，把 16 项缺口整理成**可逐项核对、可执行**的清单。

> **与既有文档的关系**
> - `docs/legacy-feature-gap-ncu.md`（2026-10 核对）给出"缺什么"及证据，本文给出"是否要补、怎么补"。
> - `docs/legacy-feature-gap-backlog.md`（2026-09-23）已过时：其中的 **R01 已实现**（路由器置信度与路由器数量策略条件），**N01 的迁移号 `059` 已被占用**（现为 `059_router_observations.sql`），通知部分改由本文 G01 承接。旧文件仅保留历史参考。
>
> **核对口径**：一个旧能力只有存在**生产调用链**才算"在用"。有类型/控制器/配置但无调用方的，归入"不建议补"。

## 汇总

| ID | 优先级 | 功能 | 核对结论 | 规模 | 依赖 |
|---|---|---|---|---|---|
| G01 | P0 | 通知发送方（出箱消费者 + 通道 + 模板 + 重试 + 测试发送） | **已确认补** | L | 无 |
| G02 | P0 | 黑名单列表与准入即时处置 | **已确认补** | M | 无 |
| G03 | P0 | 内网目标访问检测（旧"投毒行为"） | **需现场确认后启用** | M | 无 |
| G04 | P0 | 网络安全行为北向上报 | **需现场确认后启用** | M | G03 |
| G05 | P1 | "仅路由器用户发送"过滤 + 可信品牌白名单 | 待 G01 完成后补 | S | G01 |
| G06 | P1 | 动作级执行时段 / 禁止时段 | **需现场确认**是否需要动作级粒度 | S | 无 |
| G07 | P1 | AI 中转站审计台账（用量 + 指标 + 导出 + 页面） | **需现场确认**是否需要台账 | M | 无 |
| G08 | P1 | 源端口聚类共享设备信号 | 建议补，默认保守关闭 | M | 无 |
| G09 | P1 | 协议观测频次阈值 + "疑似"清单 | **需现场确认**阈值口径 | M | 无 |
| G10 | P1 | 监控告警面（仪表盘 / webhook 入库 / 告警规则 / 指标族） | 建议补（可先指标族） | M | 无 |
| G11 | P2 | 设备发现类别目录 | 建议延后 | M | 无 |
| G12 | P2 | 统计报表维度补齐 | 建议延后 | M | 无 |
| G13 | P2 | 用户组管理 | 建议延后 | S | 无 |
| G14 | P2 | 用户自助改密 | 建议延后 | S | 无 |
| G15 | P2 | 指标导出 Excel | **不建议补**（CSV 已覆盖） | S | 无 |
| G16 | P2 | 体验反馈采集页 | **不建议补** | S | 无 |

约定：PostgreSQL 迁移从 `092` 起（当前最新 `091`）；ClickHouse 本期不动（最新 `033`）。

### 本轮实施范围

按已批准计划，**本轮已落地 G01–G04**（见下表"状态"）；G05–G12 由你逐项确认后再排期；G13–G16 暂不实施。

| ID | 状态 | 落地内容 |
|---|---|---|
| G01 | **已实现（未部署现场）** | 迁移 `092_notification_delivery.sql`；`internal/notify`；`internal/controlplane/notifications.go`（模板/通道/出箱接口 + 10s 投递 worker）；`Stage.ChannelID`；出箱无通道时明确失败 |
| G02 | **已实现（未部署现场）** | `internal/policy/blacklist.go`；`internal/controlplane/whitelist.go` 泛化为双名单管理器 + `blacklist_hit` trigger；前端黑名单页 |
| G03 | **已实现（默认关闭，待现场给网段与阈值）** | 迁移 `093_destination_targets.sql`；`internal/poison`；`internal/store/destination_targets.go`；60s worker；`internal_target_access` 弱证据；回放 fixture；前端规则/发现/试算页 |
| G04 | **已实现（默认关闭，待现场给平台契约）** | 迁移 `094_behavior_reports.sql`；`internal/behaviorreport`；`internal/controlplane/behavior_reports.go`（通道/队列/试算/测试 + 15s worker）；三类事件生产者；前端通道/队列页 |

---

## P0

### G01 通知发送方

**核对结论：已确认补。** 当前系统已有出箱表与 `notify` 阶段，但没有发送方，"入队"被当成"送达"。

**旧系统落点（真实在用，唯一发得出去的链路）**

- 启动：`cmd/server/capture.go:395`（`strategy.Setup()` → `go e.Listen()`）、`:422` `company.Setup()`、`:425` `company.Engine.Listen()`。
- 投递：`pkg/component/policy/strategy/strategy.go:164` `Push` → `:182` `Listen()` → `:277` `company.Engine.Push` → `pkg/sms/company/supwisdom.go:132` `POST {ApiHost}/apis/messagecenter/v1/poaMessage/messageSend`（OAuth2，`SendType=["SMS","WECHAT"]`）。
- 正文渲染**不在本地**：只发固定 `MessageTypeCode`，参数在 `strategy.go:225-262` 硬编码（`contact_number` 缺省回退 `"83969312"`）；`template_id` 只写日志。
- 测试发送：`POST /api/policy/information/test` → socket `PolicySms` → 绕过队列直发。
- 手动发送：`POST /api/feature/judge/send-message[/batch]`（上限 100 IP）。
- 另有 `list:message:dispatcher` 链路（模板 CRUD `/api/policy/message` + `etc/template.json`），但**全仓无生产者**，不是可用能力。

**当前实现**

- `notification_outbox` 表已存在：`migrations/postgres/072_srun4k_simplified_integration.sql:69-78`（`idempotency_key` UNIQUE、`template text`、`parameters jsonb`、`status CHECK IN (queued,sent,failed,cancelled)`）。
- `notify` 阶段已校验：`internal/policy/engine.go:150-153` 要求 `Template` 非空；Action 白名单 `record/notify/rate_limit/disconnect/disable_account`（`:146-162`）。
- 原生 4K 路径写入出箱：`internal/controlplane/native_dispatch.go:139`。
- **缺陷**：全仓 Go 代码对 `notification_outbox` 的唯一引用就是这条 INSERT；**没有消费者、没有重试、`status` 永远是 `queued`**，写入后动作立刻被标记 `succeeded`（`native_dispatch.go:143`）。`Stage.Template` 是裸字符串（`engine.go:32`）原样透传（`policy_actions.go:344`）。

**落点**

- 迁移 `migrations/postgres/092_notification_delivery.sql`：
  - `ALTER TABLE notification_outbox` 增 `channel_id`、`attempts`、`next_attempt_at`、`last_error`、`rendered_payload jsonb`、`sent_at`；索引 `(status, next_attempt_at)`。
  - 新表 `notification_templates`、`notification_channels`（`encrypted_secret`，可选 `is_default` 且部分唯一索引保证至多一条）、`notification_delivery_attempts`。
- 新包 `internal/notify`：模板（白名单变量替换，不做表达式求值）、通道校验、`Sender` 接口、`httpProvider`、可插拔 `srun_sms` 预设（默认关闭）、`Backoff`（`min(2^attempt,3600)` 秒，8 次封顶）。
- 控制面 `internal/controlplane/notifications.go` + `startNotificationWorker()`（ticker 10s，`FOR UPDATE SKIP LOCKED` 领取，注册位置对齐 `server.go:483-492`）。
- 策略接入：`Stage` 增 `ChannelID`（可选，向后兼容）；`policy_actions.go:344` 透传；`native_dispatch.go:139` 解析通道（`Stage.ChannelID` → 默认通道），**解析不到直接 `status='failed'` + `last_error='未配置通知通道'`**，不再静默 `queued`。
- 密钥复用 `actions.go:1083` `encryptConnectorSecret` / `decryptConnectorSecret`。

**接口**：`/notifications/templates`、`/notifications/channels`（含 `/{id}/test`）、`/notifications/outbox`（含 `/{id}/retry|cancel`）、`POST /notifications/test`。权限 `notifications:read` / `notifications:manage`。

**前端**：`frontend/src/pages/NotificationsPage.tsx` → `/settings/notifications`（模板 / 通道 / 投递记录 / 测试发送）；策略编辑器的 `notify` 阶段改选通道 + 模板。

**验收**

- [x] 自动模式策略触发后，通道收到真实请求，`status='sent'` 且有 `sent_at` 与 attempt 行。
- [x] 失败通道按退避重试，超限置 `failed` 并留 `last_error`。
- [x] 未配置通道时接口/页面显示 `failed`，**绝不显示为已送达**。
- [x] 页面可发起测试发送并看到真实结果。
- [x] 密钥不出现在任何响应、日志、审计中。

**测试**：`internal/notify` 单测（变量白名单、未知变量报错、退避、鉴权注入）+ httptest 集成（成功/失败/重试耗尽/超时/4xx 不重试 5xx 重试）+ PG 集成（并发只领一次、状态迁移）+ 控制面测试（CRUD、加解密往返、只读拒绝、权限）。

**风险**：并发重复投递（`SKIP LOCKED` + 唯一键 + `Idempotency-Key`）、同步发送阻塞评估（全异步出箱）、通道凭据外泄（复用加密 + `json:"-"`）。

**假设**：短信/微信提供方与凭据需现场确认；本轮交付通用 HTTP 通道 + 可插拔 OAuth2 短信预设，默认关闭。

---

### G02 黑名单列表与准入即时处置

**核对结论：已确认补。** 当前只有白名单，策略触发维度里没有"名单命中"。

**旧系统落点（在用）**

- 名单 CRUD：`internal/web/controllers/policy.go:1436` `RegisterBlacklist`（`/api/policy/blacklist`，含 `/blacklist/import`）。
- 准入判定：`internal/analyze/analyze_multi.go:376` `CheckInBlack(IP/MAC/账号)`、`:382` `GetLoad`。
- 即处置：`pkg/devices/register.go:157` `SetUserWithResult`；`pkg/devices/blacklist_effect.go` 负责效果与审计。
- 定时清理：`cmd/server/capture.go:201` `StartCleanCache`。
- 现场验收：`docs/nanchang-non-shadow-regression-20260907.md:42`（`codex_live_v3_65` 黑名单准入 DM 投递恰好一条）。

**当前实现**

- 只有白名单：`internal/controlplane/whitelist.go`（存储于 `control_plane_settings` 的 `policy_whitelist_v1` JSON 文档，含 revision 冲突检测与 10000 条上限）+ 动作抑制（`policy_actions.go:112,240`）。
- 策略 trigger 仅 `quota_exceeded / session_quota_exceeded / shared_access / explicit_proxy`（`internal/policy/engine.go:77`）。
- `Stage.PutBlack`（`engine.go:36`）只是透传给连接器的动作参数，不是名单管理。

**落点**

- `internal/policy/blacklist.go`：`BlacklistEntry` 复用 `WhitelistEntry` 类型（避免复制匹配器）+ `NormalizeBlacklist` / `MatchBlacklist` / `MatchAccountBlacklist`，共用 `whitelist.go` 的 `MatchWhitelist`。
- `internal/controlplane/blacklist.go`：`blacklistManager` 镜像 `whitelistManager`（`whitelist.go:36-220`），settings key `policy_blacklist_v1`。**无需迁移**。
- 新 trigger `blacklist_hit`：`engine.go:77` 白名单加入；`Validate` 不要求设备配额（配额只属 `quota_exceeded`）；允许 `observe/manual/automatic` 与任意 stage。
- `policy_actions.go:35` `processAccountPolicies` 新增分支：
  - 命中 → `Known=true, Violated=true, Reasons=["blacklist_hit"], EvidenceIDs=[entry_id]`
  - 未命中 → `Known=true, Violated=false, Reasons=["blacklist_no_match"]`（走 recovery，条目删除/过期后释放动作）
  - **名单读取失败 → `Known=false, Reasons=["blacklist_unavailable"]`**（不动作、不误恢复）
- 白名单优先级天然保留：白名单抑制在 `Advance` 之前且对所有 trigger 生效。
- **已知约束**：`policy.Select` 的 `used[p.Trigger]` 使每个 trigger 每账号只选一条策略（`engine.go:263-296`），黑名单同样受限；如需多名单多动作需后续扩展。

**接口**：`GET/POST /blacklist`、`GET/PUT/DELETE /blacklist/{id}`、`POST /blacklist/import`；权限 `policies:read` / `policies:manage`。
**前端**：`frontend/src/pages/BlacklistPage.tsx` → `/policies/blacklist`，镜像 `WhitelistPage.tsx`。

**验收**

- [x] 命中账号在一个评估周期内产生动作；条目失效/删除后动作被释放。
- [x] 白名单账号零动作（对齐旧系统 `codex_live_v3_64`）。
- [x] 名单读取失败不产生任何误动作。
- [x] 影子/审批/冷却/审计/撤销全部沿用现有闭环。

**测试**：匹配器单测、trigger 校验单测、`processAccountPolicies` 单测（命中/未命中/名单不可用/白名单优先）、控制面 CRUD 与权限/只读测试。

---

### G03 内网目标访问检测（旧"投毒行为"）

**核对结论：能力确实缺失，但目标网段与阈值必须由现场提供——默认关闭，先交付可试算能力。**

**旧系统落点（在用，且在热路径）**

- 模型：`pkg/component/types/behavior.go:9-29`——`configured_ip_range`（访问指定内网 IP/网段）、`high_frequency_internal`（高频内网访问）；窗口固定 3600 秒；方向 up/down/bidirectional。
- 匹配：`pkg/events/behavior/matcher.go`（IP/CIDR 编译、内网判定、按设备×小时聚合）。
- 引擎：`pkg/events/behavior/engine.go:147` `CheckPoison`、`:157` `CheckDestinationIP`、`:176` `CheckPacketEndpoints`。
- 调用：`cmd/server/capture.go:372` `behavior.Setup`；`internal/analyze/analyze_multi.go:234` 逐流判定。
- 管理面：规则 CRUD `/api/policy/poison-behavior`、日志 `/api/log/poison-behavior`、页面 `/policy-configuration/poison-behavior` 与 `/log-management/poison-behavior`；命令 `cmd/status_poison_behavior.go`、`cmd/clean_poison_behavior.go`。

**当前实现**：无。全仓检索 `poison` 只命中无关注释与测试文案。

**落点**

- 迁移 `migrations/postgres/093_destination_targets.sql`：`destination_target_rules`（`behavior_type`、`target_type`、`targets text[]`、`window_seconds`、`threshold`、`direction`、`push_enabled`、`push_without_account`，`enabled` 默认 **false**）、`destination_target_findings`（含 `matched_targets`、`unique_destinations`、`hit_count`、`pushed`）。
- 新包 `internal/poison`：`Evaluate(rule, observations)` 纯函数，负责阈值/方向/窗口判定与去重（先写回放测试）。
- `internal/store/destination_targets.go`：ClickHouse 聚合 `normalized_events`（`PREWHERE timestamp`、`type IN (...)`、按 `direction`），CIDR 匹配在 Go 侧用 `netip`，带行数上限。
- Worker `startDestinationTargetWorker()`（ticker 60s，独立 goroutine）：查询 → 求值 → 写 findings → 产出 `evidence.Evidence{Type:"internal_target_access"}` 并 `WriteEvidence`。
- 风险引擎 `internal/risk/risk.go`：`internal_target_access` 计为**弱信号并封顶**，不进入自动处置资格。
- 试算：`POST /destination-targets/rules/{id}/preview`（不落库、不产证据）。

**接口**：`/destination-targets/rules`（CRUD）、`/destination-targets/findings`、`/destination-targets/rules/{id}/preview`；权限 `destination-targets:read` / `destination-targets:manage`。
**前端**：`frontend/src/pages/DestinationTargetsPage.tsx` → `/policies/destination-targets`（规则 / 发现记录 / 试算）。

**验收**

- [x] 规则默认关闭；试算结果与实际落库一致。
- [x] 开启后产出带证据/分数/置信度/窗口/解释的 `internal_target_access`，风险页与案件可见。
- [x] 单独该信号不产生自动处置。
- [x] 反例零命中：自身 IP、组播/广播、校内网关、基础设施、正常内网 DNS、NAT 复用。

**测试**：`examples/replay/destination-target-*.jsonl` 正反例 + `internal/poison` 单测 + store 查询集成测试（窗口边界、跨午夜、超时截断）。

**风险**：NAT/CGNAT 与内网服务密集造成误报 → 默认关闭、试算、反例回放、基础设施排除、弱信号封顶。查询压力 → `PREWHERE` + 行数上限 + 60s 周期。

**假设**：敏感网段与阈值由现场提供，代码不预设。

---

### G04 网络安全行为北向上报

**核对结论：能力缺失，需要补；但外部平台协议与鉴权需现场确认，默认关闭。**

**旧系统落点（在用）**

- 预设通道：`pkg/events/behavior/preset.go` `NorthboundSecurityBehaviorReportPreset` → `https://192.168.0.115:8001/api/ncu/security-behavior/report`；token `GET .../api/v1/auth/get-access-token` 放入 body 顶层。
- 上报类型：`poison_behavior`（`behavior_type=malware`）、`proxy_behavior`、`ai_relay_audit`（`pkg/component/types/behavior.go:25-27`）。
- 通道能力：批量 100 / flush 1s、重试 3 次、超时、字段映射（`source_system_ip`、`source_system_name`、`account`、`occurred_at`、`source_ip`、`target`、`target_type`、`behavior_type`）。
- 来源系统字段适配提交 `2da40cb4`；真实姓名补全 `pkg/component/northbound/setup.go:115`。
- 通道配置 API：`internal/web/controllers/southbound.go:25`（含 `behavior-governance/presets`、`/fields`、`/{id}/preview`、`/{id}/test`）。

**当前实现**：无。`security-behavior` / `behavior_type` 全仓无命中；南向只有 4K 身份桥与动作连接器。

**落点**

- 迁移 `migrations/postgres/094_behavior_reports.sql`：`behavior_report_channels`（endpoint/token/鉴权/批量/超时/`tls_skip_verify` 默认 false/`field_mapping`/`success_status_codes`，`enabled` 默认 false）、`behavior_report_outbox`（`idempotency_key` UNIQUE、`event_type`、`status`、`attempts`、`next_attempt_at`、`last_error`、`sent_at`）、`behavior_report_attempts`。
- 新包 `internal/behaviorreport`：通道校验、字段映射渲染、`Sender.Send(ctx, batch)`（支持 `oauth2_client_credentials` 取 token、`tls_skip_verify` 默认关闭）、`Backoff`。
- Worker `startBehaviorReportWorker()`（ticker 15s）：按通道批量领取、投递、写 attempts、更新状态；超限置 `failed`。
- 生产者（幂等键 = `hash(event_type, subject, target, window)`）：G03 `push_enabled` findings → `poison_behavior`；`proxy_protocol_transaction` 证据 → `proxy_behavior`（仅审计）；`ai_relay_domain_usage` 证据 → `ai_relay_audit`；`push_without_account` 控制无账号是否上报。
- 控制面 `internal/controlplane/behavior_reports.go`：通道 CRUD、出箱列表/详情、单条重试/取消、测试发送与试算。

**接口**：`/behavior-reports/channels`（CRUD + `/{id}/test|preview`）、`/behavior-reports/outbox`（含 `/{id}/retry|cancel`）；权限 `behavior-reports:read` / `behavior-reports:manage`。
**前端**：`frontend/src/pages/BehaviorReportsPage.tsx` → `/settings/behavior-reports`（通道 / 投递队列 / 试算）。

**验收**

- [x] 配置通道后，G03 命中与代理/AI 中继证据按批上报。
- [x] 重复事件不重复上报（幂等键）。
- [x] 失败可重试并留 `last_error`；投递状态可查。
- [x] 密钥不出现在日志与响应。

**测试**：字段映射表驱动单测、httptest 集成（token 获取/批量/部分失败/重试耗尽/成功码/TLS 默认校验）、PG 集成（幂等去重、并发领取、状态迁移）、生产者幂等单测。

**假设**：上报地址、鉴权与字段契约以现场为准；实现镜像旧系统形态但全部可配置，默认关闭。

---

## P1

### G05 "仅路由器用户发送"过滤 + 可信品牌白名单

**核对结论：待 G01 完成后补（依赖明确）。**

- 旧系统由动作参数 `router_only_notify` 实现：`pkg/devices/register.go:210-213` `shouldSkipRouterOnlyNotification`（`enabled && routerOnly && !ConfirmedRouter` → 抑制 `msg_notify`）；判定 `pkg/devices/router_confidence.go:19-41`。
- 可信条件三重：设备类型 `router`、能建立稳定逻辑身份、品牌在白名单。**代码白名单比文档宽**：`tp-link/broadlink/dlink/feixun/ubiquiti/mercury/huawei`（huawei 仅对已被路由器证据提升的记录）+ 显式允许 `h3c`。
- **注意**：`ConfirmedRouter` 依赖 `networkdevice.IsConfirmedRouterIP`，在 `router_recognition.shadow_mode`（默认 true）下恒 false（`pkg/networkdevice/repository.go:246-248`），故默认会抑制全部消息；南昌现场是靠 `--policy-shadow-mode=false` 才生效。
- 当前系统路由器证据已具备（`internal/evidence/router.go` 的 `Assessment.ConfirmedRouter`，含 `Brand/Role/Strength/Infrastructure/Ambiguous/AssociationQuality`），G01 完成后可直接挂接为 notify 阶段的一个条件。
- **落点建议**：`Stage` 增 `RouterOnly bool`（或在 `Stage` 增加条件子结构），校验与影子行为对齐现有闸门；前端策略编辑器加开关。

### G06 动作级执行时段 / 禁止时段

**核对结论：需现场确认是否真的需要动作级粒度。**

- 旧系统每动作可独立配置：`third_party/antipolicy/engine/evaluator.go:288-293`（`execution_time_start/end`，兼容旧键 `blocked_time_start/end` 作为禁止时段）；另 `:179-188` `first_duration/duration`、`:211-216` `repeat_interval/interval`、`:250-276` `count/trigger_count`。
- 当前系统时段只在**策略级** `Scope`（`internal/policy/engine.go:21-23` `Weekdays/StartMinute/EndMinute`）；`DurationSeconds / IntervalSeconds / DependsOn / MinEpisodes` 已对应旧的 duration/interval/depends_on/trigger_count。
- **差异**：同一策略无法给"消息"和"下线"设不同时段，也无法表达"某时段禁止执行"。
- **落点建议**：`Stage` 增 `ExecutionStartMinute/ExecutionEndMinute *int`（跨午夜语义对齐旧实现，时区固定 Asia/Shanghai），在 `Advance` 的 stage 执行前判定；或确认现场可用策略级时段替代后关闭本项。

### G07 AI 中转站审计台账

**核对结论：需现场确认是否需要台账（当前只有一条风险信号）。**

- 旧系统 `pkg/airelay/`（1774 行）：`Observation` 用量流水、`AccountAttribution` 账号归属、`Indicators` CRUD + override 校验、`Backfill`；API `/api/ai-relay/summary|usages|usages/export|usages/:id|indicators`；页面 `/log-management/ai-relay`。
- 当前 `internal/airelay/airelay.go`（297 行）只作为证据匹配器（`internal/evidence/evidence.go:349` `airelay.Default()`，证据类型 `ai_relay_domain_usage`）；无用量流水、无指标管理、无导出、无页面。
- **落点建议**：若要补，新增 `ai_relay_usages` 表 + 指标覆盖表 + 导出（复用 `internal/controlplane/exports.go` 的异步导出）+ 页面；若不需要，在风险页把 `ai_relay_domain_usage` 的证据详情做足即可。

### G08 源端口聚类共享设备信号

**核对结论：建议补，默认保守关闭。**

- 旧系统：`pkg/capture/classifier/classifier_new.go`（源端口递增间隔聚类，动态阈值 `avgTrend*1.5+10`、最少 20 端口、2–3 簇、跨度 >1000）、`pkg/capture/resolve/port.go`；由 CLI `--enable_cluster` 开启（`cmd/server/capture.go:85`），**默认关闭**。
- 当前共享接入信号组：`ua_os / ttl_path / tls_stack / tcp_stack / dhcp_stack / confirmed_same_exit_endpoints`（`internal/sharedaccess/evaluate.go:212-227`），无端口形态。
- **落点建议**：作为第五类独立信号加入 `internal/evidence`（端口序列聚类）+ `internal/sharedaccess`，必须满足现有"重复共现"要求，不能单靠该信号定性；默认关闭，先写正反例回放（NAT/CGNAT 误报风险）。

### G09 协议观测频次阈值与"疑似"清单

**核对结论：需现场确认阈值口径，且要先厘清与现有信号的层级。**

- 旧系统：`pkg/capture/member/ip_feature.go:47-116`、`ip_suspected.go:42-116`；阈值来自 `etc/dpi.yaml:55 thresholds:`（SNI/HTTP/TLSVersion/CipherSuite/DNS/QUIC/SNMP/Session，默认 200）；查询 `/api/feature/judge/suspected`；页面 `/reports-management/anti-proxy/suspected`。
- 当前：无按协议阈值。`SuspectedDeviceCount`（`internal/store/device.go:900`）语义是"推断设备数"，与协议频次无关；未提交的 `internal/store/protocol_attribution.go` 是把 HTTP Server/TLS 证书/JA3 通过唯一 DHCP 租约归属到设备，也不是频次阈值。
- **落点建议**：按协议可配置阈值 + 独立"疑似"清单（查询接口 + 页面）；**必须明确与 `domain_diversity`（≥20 域名）/`port_distribution`（≥5 目的端口）的层级，避免同一现象重复计分**。

### G10 监控告警面

**核对结论：建议补，可按"先指标族、再告警规则、最后仪表盘"分步。**

- 旧系统：Prometheus exporter（`pkg/component/metrics`）、Grafana 反代（`internal/web/router/router.go:29` `api.Any("/grafana/*proxyPath")`）、Grafana 告警 webhook 入库（`POST /api/webhook`）、报告 `GET /api/monitor/report`；页面 `/system-management/monitor`。
- 当前：`/metrics` 28 个指标族（`internal/controlplane/health.go`、`application_metrics.go`、`identity_metrics.go`）；固定 ingest lag / 坏行率 webhook（`internal/realtime/worker.go:42,241-244`）；**无仪表盘、无 webhook 入库、无可配置告警规则与静默窗口**；缺风险/证据/案件/策略执行/处置/共享接入指标族。
- **注意**：旧系统的告警策略引擎本身不可达（`pkg/devices/proxy.go:324` `alert.Engine.Check` 被注释），所以这里应**重新设计**而不是平移。

---

## P2（建议延后或不做）

| ID | 功能 | 核对结论 | 说明 |
|---|---|---|---|
| G11 | 设备发现类别目录 | 建议延后 | 旧系统 `pkg/component/types/mdns.go` 67 条服务→设备类别 + 页面 `/discover/{airplay,camera,...}`；当前 `internal/discovery/model.go:170-205` 只映射**能力**且有意不把服务公告当整机类型（符合证据可信度规范）。若要按类别浏览，应作为"能力视图"而非"设备类型结论"呈现 |
| G12 | 统计报表维度 | 建议延后 | 旧 15 个 `/api/report/*` 端点；当前 `/dpi/*` + `/activity/reports?dimension=` 已覆盖主要维度。缺设备品牌/型号/OS/渠道统计、路由器处罚统计、策略触发趋势、消息统计 |
| G13 | 用户组管理 | 建议延后 | 旧 `/api/user-groups` CRUD；当前只有固定角色（`internal/controlplane/security.go:213-224`）。旧系统的用户组是**未强制**的元数据（`CheckInterfaceAuthority` 零调用方），属管理便利而非安全缺口 |
| G14 | 用户自助改密 | 建议延后 | 旧 `POST /api/change-password`；当前仅管理员可重置他人密码（`internal/controlplane/users.go:163`） |
| G15 | 指标导出 Excel | **不建议补** | 旧 `GET /api/export/excel` 只是把 Prometheus 查询结果导出 xlsx；当前 CSV 异步导出（`POST /api/v1/exports`）业务价值更高 |
| G16 | 体验反馈采集页 | **不建议补** | 无实际运营需求 |

---

## 明确不建议补（旧系统不可达）

以下能力在南昌分支**没有生产调用方**，不要为对齐而补。详见 `docs/legacy-feature-gap-ncu.md` §四。

| 旧能力 | 不可达证据 | 当前替代 |
|---|---|---|
| License 授权强制 | `cmd/server/capture.go:178-181` 校验被注释 | 商业策略，单独决策 |
| 告警策略执行 | `pkg/devices/proxy.go:324` `alert.Engine.Check` 被注释 | 由 G10 重新设计 |
| 准入策略引擎 | `cmd/server/capture.go:402` `access.Setup()` 被注释 | 策略 `Scope` + 黑名单（G02） |
| GeoIP 归属 | `internal/analyze/analyze_multi.go:273` maxmind 调用被注释 | 如需再评估 |
| 日志备份/恢复 | backup 路由组整体注释；`pkg/task` 引用不存在的包 | 部署层备份 |
| CAPWAP 解码 | `internal/analyze/handle/capwap.go` 无调用方 | 无需求 |
| 自研 LLMNR/NBNS 解码 | `pkg/layers_handle/**` 未被 import | Zeek `nbns.log`/`llmnr.log` 已接入 |
| RBAC 接口鉴权 | `pkg/manager/impl.go:397` `CheckInterfaceAuthority` 零调用方 | 当前强制 `rolePermissions` |
| 端口熵阈值 | `pkg/capture/classifier/setup.go:28` `EnableEntropy:false` | 无需求 |
| 打印机 WebSocket | 路由组注释且引用了不存在的 `websockets.List()` | 无需求 |
| 声明式条件求值器 | `third_party/antipolicy/condition` 整包零 import | 策略 `Scope` 已覆盖 |
| socket 空处理器 | `MessageEngine`(=17) 空实现；`NorthboundInterface`(=15) 函数体为空；`PrinterDevices`(=8) 未注册 | 无需求 |
| 孤儿包 | `pkg/layers_handle`、`pkg/component/mac_oui`、`pkg/component/pprof` 无任何 import | 无需求 |
| 加密/鉴权弱点 | JWT 密钥硬编码、密码明文存储、SM4 密钥硬编码并打印 stdout、北向 token 无过期 | 当前为 OIDC + 哈希口令 + 强制 RBAC + 会话失效 |

---

## 建议执行顺序

1. **G01 通知发送方** —— 出箱表与 `notify` 阶段已就位，是最短路径；其余处置策略的运营前置能力。
2. **G02 黑名单准入** —— 无迁移、复用白名单模式与既有策略闭环。
3. **G03 内网目标访问检测** —— 先回放测试，默认关闭，等现场给网段与阈值。
4. **G04 网络安全行为北向上报** —— 依赖 G03 产出的 finding，并消费既有代理/AI 中继证据。
5. **G05** —— G01 完成后的小改动。
6. **G08 / G09 / G10** —— 按现场需求排期；G09 先厘清与现有信号的层级。
7. **G06 / G07** —— 待现场确认是否真的需要。
8. **G11–G16** —— 延后或不做。

## 通用完成定义（DoD）

- 新增采集/派生信号：先适配标准事件，风险引擎不得读取后端原始字段。
- 新增证据：必须返回证据、分数、置信度、窗口和解释文本，并带样本。
- 新增动作：必须支持影子模式、冷却、审计日志与人工撤销。
- 先有回放 fixture 与 Go 测试，再考虑真实流量。
- 新接口必须进 OpenAPI 契约并重生成前端类型；新增路径必须在 `requiredPermission` 显式分支。
- 前端改动：`tsc --noEmit` 与生产构建通过；三视口检查；遵守缺省值与对比度规范。
- 涉及外部系统（G04）或现场阈值（G03）的能力，默认关闭并标注"需现场确认"。
