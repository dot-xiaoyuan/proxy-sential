# 旧 dpi-analyze（南昌大学定制版）与 Proxy Sentinel 功能对比

本文对比 **旧系统现场分支** `dpi-analyze-定制-南昌大学`（origin `srun/products/dpi-analyze`，最新提交 `1a707a8d`，2026-09-24）与当前 `proxy-sentinel`（HEAD `364ec17`，2026-10-10），回答**当前系统还有哪些旧能力没有实现**。

> 与既有文档的关系：`docs/legacy-feature-gap.md`（2026-09-23）分析的是**基础版** `dpi-analyze`，不是南昌定制分支；且其结论已落后约 3 周（当前迁移已从 `058/016` 推进到 `091/033`）。本文以南昌分支的实际调用链为准重做核对。凡本文与旧文档冲突，以本文为准。

## 一、对比口径与规模

| 维度 | 旧系统（南昌定制） | 当前系统 |
|---|---|---|
| 时间 | 2026-09-24 | 2026-10-10 |
| Go 文件 / 行数 | 351 / 5.15 万 | 647 / 11.11 万 |
| 采集 | 自研 AF_PACKET + gopacket TCP 重组 | Suricata / Zeek 适配 + 自研 AF_PACKET 设备信号与发现 + SNMP + IEEE1905（AF_XDP / DPDK 未实现，仍在路线图） |
| 存储 | MongoDB / Redis / Elasticsearch | PostgreSQL（91 迁移）/ ClickHouse（33 迁移） |
| 前端 | 单包构建产物（`internal/web/build`，提取 80 条前端路由；后端 95 条路由注册） | React 源码 38 个页面 + 类型化导航 |
| 进程 | capture + web 双进程，Unix socket | systemd 多进程（ingest / controlplane / worker） |

**判定标准**：一个旧能力只有存在**生产调用链**才算"在用"。有类型/控制器/配置但无调用方的，标为"旧系统内已不可达"，不计入当前缺口。

**结论先行**：检测、证据、风险、处置、身份与存储层，当前系统已全面超过南昌旧系统。**尚未实现的真实缺口集中在四块：① 通知的"最后一公里"（出箱表已建但无人消费）与名单准入运营闭环；② 南昌现场特有的行为上报（投毒行为检测 + 网络安全行为北向）；③ 部分补充检测信号与报表维度；④ 监控告警与少量运营便利项。**

---

## 二、仍未实现（缺口清单）

### 汇总

| ID | 优先级 | 功能 | 规模 | 现场影响 |
|---|---|---|---|---|
| G01 | P0 | 消息通知：出箱消费者 + 通道 + 模板渲染 + 重试/送达状态 + 测试与手动发送 | L | 出箱表只写不读，通知实际发不出去 |
| G02 | P0 | 黑名单列表与准入即时处置 | M | 名单驱动的即时下线无法配置 |
| G03 | P0 | 投毒行为检测（内网目标段 / 高频内网访问） | M | NCU 上报行为缺一类 |
| G04 | P0 | 网络安全行为北向上报（behavior governance） | M | 外部安全平台拿不到 DPI 事件 |
| G05 | P1 | "仅路由器用户发送"过滤 + 可信品牌白名单 | S | 依赖 G01 |
| G06 | P1 | 动作级执行时段 / 禁止时段 | S | 同一策略无法分时段处置 |
| G07 | P1 | AI 中转站审计台账（用量+指标+导出+页面） | M | 由台账退化为单条风险信号 |
| G08 | P1 | 源端口聚类共享设备信号 | M | 少一类独立信号 |
| G09 | P1 | 协议观测频次阈值 + "疑似"清单 | M | 少按协议的可配置阈值 |
| G10 | P1 | 监控告警面（Grafana 反代 / webhook 入库 / 告警规则 / 指标族） | M | 运维可观测性弱 |
| G11 | P2 | 设备发现类别目录（airplay/camera/display/iot/printer/windows/macos） | M | 按类别浏览能力弱 |
| G12 | P2 | 统计报表维度（设备品牌/型号/OS/渠道、路由器处罚、策略趋势、消息） | M | 报表维度少 |
| G13 | P2 | 用户组管理 | S | 只有固定四角色 |
| G14 | P2 | 用户自助改密 | S | 只能管理员重置 |
| G15 | P2 | 指标导出 Excel | S | 低价值，可延后 |
| G16 | P2 | 体验反馈采集页 | S | 低价值 |

---

### P0

#### G01 用户消息通知子系统

**旧系统：实际有两条链路，只有一条在真正发送**

链路 A（**在用，唯一真正发消息的**）：

- 启动装配：`cmd/server/capture.go:395`（`strategy.Setup()` → `go e.Listen()`）、`:422` `company.Setup()`、`:425` `company.Engine.Listen()`。
- 投递路径：`strategy.Engine.Push`（`pkg/component/policy/strategy/strategy.go:164`，Go channel cap 100，满则报"消息发送队列已满"）→ `engine.Listen()`（`:182`）→ `company.Engine.Push`（`:277`，Go channel）→ `sendSms` → **Supwisdom 消息中心** `POST {ApiHost}/apis/messagecenter/v1/poaMessage/messageSend`（`pkg/sms/company/supwisdom.go:132`，OAuth2 client-credentials，scope `messagecenter:v1:sendMessage`，`SendType=["SMS","WECHAT"]`）。
- 正文渲染**不在本地**：只发固定 `MessageTypeCode`（`supwisdom.go:76,97`），参数在 `strategy.go:225-262` 硬编码填充（account / ip / mac / brand / student_id / contact_number / date），`contact_number` 缺省回退硬编码 `"83969312"`；真实姓名走 `pkg/component/northbound`（`strategy.go:217-224`）。`template_id` 只写进消息日志，不参与渲染。
- 发送日志：Mongo `log.message_log`（`pkg/logs/message_log.go`）。
- 测试发送：`POST /api/policy/information/test`（`internal/web/controllers/policy.go:734`）→ socket `PolicySms` → **绕过队列直发**（`internal/socket/handler/policy.go:48-130`，含硬编码测试数据）。
- 手动发送：`POST /api/feature/judge/send-message`、`/send-message/batch`（上限 100 个 IP，`internal/web/controllers/feature.go:76-159`）。
- 动作侧：`third_party/antipolicy/action/builtin/msg_notify.go` ← `pkg/devices/register.go:215` `queuePolicyMessage`（要求 `params.template_id`）← `pkg/devices/proxy.go:314` 策略评估。附带消息由 `force_offline` / `bandwidth_reduction` / `user_disable` 在 `params.sync_msg==true` 时复用同一入口。

链路 B（**有消费端、无生产端，永远不发**）：

- `list:message:dispatcher`（`pkg/component/types/message.go:4`）→ dispatcher（`pkg/component/message/setup.go:45,86` → `BLPop`）→ message-engine SRun provider（`POST https://{Host}:8001/api/v2/short/sms`）。
- 模板 CRUD `/api/policy/message`（`controllers/policy.go:959`）与模板文件 `{EtcDir}/template.json`（`pkg/component/message/setup.go:80`）属于这条链路。
- **全仓（含 `third_party`、`scripts`、`tools`、外部模块 `message-engine@v1.0.4`）没有任何代码向该 Redis List 写入**；仓库内也不存在 `etc/template.json`。因此模板与通道配置改动不影响任何实际发送。
- 通道配置：`/api/policy/information`（`:667`）为 Supwisdom 配置；`/api/policy/message/information`（`:1005`）为链路 B 的 vendor 配置。

**旧系统的渠道只有短信 + 微信**（无邮件 / 通用 webhook）。

**当前系统：有"出箱表"，但没有发送方——比"完全没有"更接近，但同样送不出去**

已具备的部分：

- `notification_outbox` 表存在（`migrations/postgres/072_srun4k_simplified_integration.sql:69-78`）：`notification_id` / `idempotency_key`（UNIQUE）/ `account_id` / `template text NOT NULL` / `parameters jsonb` / `status CHECK IN (queued,sent,failed,cancelled)` / 时间戳。
- `notify` stage 已纳入策略校验：`Template` 为空直接报错（`internal/policy/engine.go:150-153`），Action 白名单为 `record / notify / rate_limit / disconnect / disable_account`（`:146-162`）。
- 原生 4K 连接器路径会把通知写入出箱：`internal/controlplane/native_dispatch.go:139` `INSERT INTO notification_outbox(...) VALUES(...)`（`template = a.PolicyParameters.Template`，`parameters = {action_id, policy_execution_id}`，`ON CONFLICT(idempotency_key) DO NOTHING`），随后把动作标记 `succeeded`（execution id = `notification-<idempotency>`）并写审计 `enforcement.notification_queued`。
- 非原生连接器路径要求连接器声明 `session.notify` 动作映射（`internal/controlplane/policy_actions.go:274`），即委托给旧北向连接器。

缺失的部分（这是真正的缺口）：

- **`notification_outbox` 是只写的**：全仓 Go 代码对它的唯一引用就是上面那条 INSERT。**没有消费者、没有发送方、没有重试 worker**，`status` 永远不会从 `queued` 迁到 `sent`/`failed`，也没有任何接口能查询投递状态。
- 没有模板存储与变量渲染：`Stage.Template` 是裸字符串（`internal/policy/engine.go:32`），原样透传（`policy_actions.go:344`），不做占位替换，也不校验模板是否存在。
- 没有通道配置（短信 / 邮件 / webhook 通道表与密钥管理），没有测试发送，没有手动按 IP / 批量发送（旧系统 `POST /api/feature/judge/send-message[/batch]` 的等价物）。
- 没有管理页面（模板 / 通道 / 投递记录）。

**结论**：当前系统已经把"通知"落到了出箱表，但链路断在出箱之后——**记录成 `queued` 即被当作动作成功，实际不会发出任何消息**。相比旧系统真正在跑的"策略命中 → Supwisdom 短信/微信"（`pkg/sms/company/supwisdom.go:132`），当前缺的是发送方与配套管理面。补齐时不必照搬旧系统的模板 CRUD 与 Redis dispatcher（那条链在旧系统自身就没有生产者），但必须提供：**出箱消费者 + 真实通道（至少短信/微信或通用 webhook）+ 可配置参数映射/模板 + 重试与 sent/failed 状态回写 + 测试发送 + 查询与页面**。

#### G02 黑名单列表与准入即时处置

**旧系统（在用）**

- 名单 CRUD：`internal/web/controllers/policy.go:1436` `RegisterBlacklist`（`/api/policy/blacklist`）。
- 准入判定：`internal/analyze/analyze_multi.go:376` `CheckInBlack(IP/MAC/账号)`，`:382` `GetLoad`。
- 即处置：`pkg/devices/register.go:157` `blacklist.Engine.SetUserWithResult`；`pkg/devices/blacklist_effect.go` 负责效果与审计。
- 定时清理：`cmd/server/capture.go:201` `blacklist.StartCleanCache`。
- 现场验收：`docs/nanchang-non-shadow-regression-20260907.md:42`（`codex_live_v3_65` 黑名单准入 DM 投递一条）。

**当前系统**

- 只有白名单（`internal/controlplane/whitelist.go`）与校园例外（`internal/controlplane/exceptions.go`）。
- 策略触发类型仅 `quota_exceeded / session_quota_exceeded / shared_access / explicit_proxy`（`internal/policy/engine.go:77`），**没有"名单命中"这一触发维度**。
- `Stage.PutBlack`（`internal/policy/engine.go:36`）只是透传给连接器的动作参数，不是名单管理。

**结论**：黑名单"名单 → 准入 → 即时动作"这条链路缺失；只能靠人工在处置页下发，或依赖 4K 侧名单。

#### G03 投毒行为检测

**旧系统（在用，且在热路径）**

- 模型：`pkg/component/types/behavior.go:9-29`——`configured_ip_range`（访问指定内网 IP/网段）、`high_frequency_internal`（高频内网访问），采样窗口固定 3600 秒，方向 up/down/bidirectional。
- 规则匹配：`pkg/events/behavior/matcher.go`（IP/CIDR 编译、内网判定、按设备×小时聚合）。
- 引擎：`pkg/events/behavior/engine.go:147` `CheckPoison`、`:157` `CheckDestinationIP`、`:176` `CheckPacketEndpoints`、`:208` `PushProxyRecord`。
- 调用：`cmd/server/capture.go:372` `behavior.Setup`；`internal/analyze/analyze_multi.go:234` 逐流 `CheckPacketEndpoints`；`pkg/devices/proxy.go:496` `PushProxyRecord`。
- 管理面：规则 CRUD `/api/policy/poison-behavior`（`internal/web/controllers/poison_behavior.go`）、`internal/socket/handler/poison_behavior.go`；日志 `/api/log/poison-behavior`；页面 `/policy-configuration/poison-behavior`、`/log-management/poison-behavior`；维护命令 `cmd/status_poison_behavior.go`、`cmd/clean_poison_behavior.go`。

**当前系统**：全仓检索 `poison` 只命中无关注释与测试文案（`internal/legacy4k/resource_bounds_integration_test.go:86`），无该能力。

**结论**：缺失。这是 NCU 明确要求上报的"网络安全行为"之一。

#### G04 网络安全行为北向上报（behavior governance）

**旧系统（在用）**

- 预设通道：`pkg/events/behavior/preset.go` `NorthboundSecurityBehaviorReportPreset`，目标 `https://192.168.0.115:8001/api/ncu/security-behavior/report`；`GET .../api/v1/auth/get-access-token` 取 token 放到请求体 `access_token`。
- 上报事件类型：`poison_behavior`（`behavior_type=malware`）、`proxy_behavior`、`ai_relay_audit`（`pkg/component/types/behavior.go:25-27`）。
- 通道能力：批量（100 条 / 1 秒 flush）、重试 3 次、超时、字段映射（`source_system_ip` / `source_system_name` / `account` / `occurred_at` / `source_ip` …）、成功判定。
- 来源系统字段适配：提交 `2da40cb4`「完成网络安全行为上报来源系统字段适配」。
- 真实姓名补全：`pkg/component/northbound/setup.go:35` `Setup`、`:115` `GetUserRealName`。
- 通道配置 API 与页面：`internal/web/controllers/southbound.go:25` `RegisterSouthbound` → `GET /api/southbound`、`GET /api/southbound/behavior-governance/{presets,fields}`、`POST /api/southbound/:id/{preview,test}`、`PUT /api/southbound/:id`；页面 `/api/southbound-management`（`router.go:254-256`）。另有入站 Grafana webhook `POST /api/webhook`（公开路由）。
- 加密/告警无关的旁路：旧系统还提供 `/api/northbound`（SRun 北向 SDK 配置，`internal/web/controllers/northbound.go:18`）。

**当前系统**：检索 `security-behavior` / `behavior_type` 无命中；南向只有 4K 身份桥（`internal/legacy4k`）与动作连接器，没有行为事件外发。

**结论**：缺失。现场外部安全平台无法获得 DPI 侧的投毒/代理/AI 中转行为事件。

---

### P1

#### G05 "仅路由器用户发送"过滤 + 可信品牌白名单

- 旧系统由动作参数 `router_only_notify` 实现：`pkg/devices/register.go:210-213` `shouldSkipRouterOnlyNotification`（`enabled && routerOnly && !input.ConfirmedRouter` → 抑制 `msg_notify`），判定函数 `pkg/devices/router_confidence.go:19-41` `isConfirmedRouterDevice`。
- 可信条件为三重（`docs/nanchang-router-detection-and-notification.md:33` + 代码）：设备类型 `router`、能建立稳定逻辑身份（`logicalDeviceFingerprint` 返回 trusted）、归一化品牌在白名单内。**代码白名单比文档更宽**：`tp-link / broadlink / dlink / feixun / ubiquiti / mercury / huawei`（huawei 仅对已被路由器证据提升的记录生效），另外显式允许 `h3c`（`router_confidence.go:19-41`）。
- **注意默认被闸住**：`ConfirmedRouter` 依赖 `networkdevice.IsConfirmedRouterIP`，而它在 `router_recognition.shadow_mode`（默认 true）下直接返回 false（`pkg/networkdevice/repository.go:246-248`）。因此默认配置下"仅路由器用户发送"会抑制全部消息；南昌现场是靠 `--policy-shadow-mode=false` 才生效。
- 当前系统无消息动作，故无该开关；路由器证据本身已具备（`internal/evidence/router.go` 的 `Assessment.ConfirmedRouter`，含 `Brand`/`Role`/`Strength`/`Infrastructure`/`Ambiguous`/`AssociationQuality`），补齐 G01 后可直接挂接。
- **依赖 G01。**

#### G06 动作级执行时段 / 禁止时段

- 旧系统每个动作可独立配置：`third_party/antipolicy/engine/evaluator.go:288-293`（`execution_time_start` / `execution_time_end`，以及 `blocked_time_start` / `blocked_time_end` 禁止时段）；另 `:179-188` `first_duration`/`duration`、`:211-216` `repeat_interval`/`interval`、`:250-276` `count`/`trigger_count`。
- 当前系统时段只在**策略级** `Scope`（`internal/policy/engine.go:21-23` `Weekdays` / `StartMinute` / `EndMinute`），`Stage` 没有独立时段；`DurationSeconds` / `IntervalSeconds` / `DependsOn` / `MinEpisodes` 已对应旧的 duration / interval / depends_on / trigger_count。
- **差异**：同一策略无法给"消息"和"下线"设不同执行时段，也无法表达"某时段禁止执行"。

#### G07 AI 中转站审计台账

- 旧系统 `pkg/airelay/`（1774 行）：`Observation` 用量流水、`AccountAttribution` 账号归属、`Indicators` 指标 CRUD + override 校验、`Backfill`；API `/api/ai-relay/summary|usages|usages/export|usages/:id|indicators`；页面 `/log-management/ai-relay`；提交 `1a707a8d`「修复AI中转站仅审计记录并关闭启动回扫」。
- 当前系统 `internal/airelay/airelay.go`（297 行）只作为**证据匹配器**（`internal/evidence/evidence.go:349` `airelay.Default()`，证据类型 `ai_relay_domain_usage`）；无用量流水、无指标管理、无导出、无页面。
- **差异**：现场"AI 中转站审计"从可查询台账退化为一条风险信号。

#### G08 源端口聚类共享设备信号

- 旧系统：`pkg/capture/classifier/classifier_new.go`（源端口递增间隔聚类，动态阈值 `avgTrend*1.5+10`、最少 20 端口、2–3 簇、跨度 >1000）、`pkg/capture/resolve/port.go`，由 `config.EnableCluster` 开启。
- 当前系统共享接入的独立信号组只有 `ua_os / ttl_path / tls_stack / tcp_stack / dhcp_stack / confirmed_same_exit_endpoints`（`internal/sharedaccess/evaluate.go:212-227`），**无端口形态**。
- 补充证据性质，非阻塞项；NAT/CGNAT 误报风险高，默认应保守。

#### G09 协议观测频次阈值与"疑似"清单

- 旧系统：`pkg/capture/member/ip_feature.go:47-116`、`ip_suspected.go:42-116`，阈值来自 `dpi.yaml thresholds.*`（SNI / HTTP / TLSVersion / CipherSuite / DNS / QUIC / SNMP / Session，默认 200）；查询 `/api/feature/judge/suspected`；页面 `/reports-management/anti-proxy/suspected`。
- 当前系统：无按协议可配置阈值。`SuspectedDeviceCount`（`internal/store/device.go:900`）语义是"推断设备数"的疑似，与协议频次无关；未提交的 `internal/store/protocol_attribution.go` 是把 HTTP Server / TLS 证书 / JA3 通过唯一 DHCP 租约归属到设备，也不是频次阈值。
- 与 `domain_diversity`（≥20 域名）/ `port_distribution`（≥5 目的端口）语义有重叠，补之前需先明确层级，避免同一现象重复计分。

#### G10 监控告警面

- 旧系统：Prometheus exporter（`pkg/component/metrics`，指标族远多于当前）、Grafana 反向代理（`internal/web/router/router.go` `api.Any("/grafana/*proxyPath")`）、Grafana 告警 webhook 入库（`POST /api/webhook` → `internal/web/controllers/grafana.go`）、报告 `GET /api/monitor/report`；页面 `/system-management/monitor`。
- 当前系统：`/metrics` 有 28 个指标族（`internal/controlplane/health.go`、`application_metrics.go`、`identity_metrics.go`），只有固定的 ingest lag / 坏行率 webhook（`internal/realtime/worker.go:42` `AlertWebhook`、`:241-244`）；**没有** Grafana、webhook 入库、可配置告警规则与静默窗口、监控页面；缺风险 / 证据 / 案件 / 策略执行 / 处置动作 / 共享接入指标族。

---

### P2

| ID | 功能 | 旧系统落点 | 当前状态 |
|---|---|---|---|
| G11 | 设备发现类别目录 | `pkg/component/types/mdns.go` 67 条服务→设备类别（Printer/IoT/Camera/Display/Router/Airplay…）；页面 `/discover/{airplay,camera,display,iot,macos,printer,windows,router}` | `internal/discovery/model.go:170-205` 只映射 printing/scanning/casting/media_rendering/network_video **能力**，且有意不把服务公告当整机类型；`DiscoveryPage` 只有 routers/devices/sources/scan/tasks。当前更保守（符合证据可信度规范），但按类别浏览能力弱 |
| G12 | 统计报表维度 | `/api/report/{proxy/top, device/{type-distribution,brand-top,os-distribution,channel-stats}, router/{overview,top,brand-distribution,punish-stats}, policy/{action-stats,trigger-trend}, user/{online-trend,activity-stats}, alert/{alert-stats,message-stats}}` | 当前 `/dpi/{overview,trends,protocol-flows,fingerprint-conflicts}`、`/activity/reports?dimension=`（application/domain/http_host/tls_sni/quic_sni/protocol/dst_port/src_ip/ecosystem）。缺设备品牌/型号/OS/渠道统计、路由器处罚统计、策略触发趋势、消息统计 |
| G13 | 用户组管理 | `/api/user-groups` CRUD；页面 `/system-management/user-group` | 当前只有固定角色 viewer/reviewer/operator/admin（`internal/controlplane/security.go:213-224`），无用户组 |
| G14 | 用户自助改密 | `POST /api/change-password`；页面 `/system-management/change-password` | 当前仅管理员可重置他人密码（`internal/controlplane/users.go:163`），登录用户无自助改密入口 |
| G15 | 指标导出 Excel | `GET /api/export/excel`（Prometheus query_range → xlsx） | 当前 CSV 异步导出（`POST /api/v1/exports`，覆盖风险/证据/案件/动作/审计）业务价值更高，故低优先级 |
| G16 | 体验反馈采集 | 页面 `/experience/feedback`、`/experience/submit-feedback` | 无 |

---

## 三、已补齐（旧文档列过、当前已实现）

| 旧文档缺口 | 当前实现 |
|---|---|
| 路由器置信度信号 | `internal/evidence/router.go:226` `confirmed_router` 证据，带 Score/Strength/RuleID/Explanation/Infrastructure/Ambiguous |
| 路由器数量策略条件 | `internal/policy/engine.go:308` `RouterCount`、`internal/policy/identity.go:157,287`；提交 `364ec17`（注：提交信息标注"尚未部署现场"） |
| 采集账本 / 实时采集 / 可观测 / 旧身份桥 / 旧北向桥 / 新旧对账 / 局域网 TTL / 指纹精华 / 黄金回放 / OIDC / 运营输出 | `docs/legacy-essentials-implementation.md` T01–T12 全部落地 |
| 白名单/VIP 命中后禁止一切处置（旧语义见 `docs/nanchang-router-detection-and-notification.md:37-39`） | `internal/controlplane/whitelist.go` + 动作抑制（`policy_actions.go:112,240`）、审批预览拦截（`policy_approval_preview.go:77`）、共享断开拦截（`shared_disconnect.go:172`） |
| 降速 / 强制下线 / 用户禁用 | `Stage.Action` 支持 `record / notify / rate_limit / disconnect / disable_account`（`internal/policy/engine.go:146-162`），含影子模式、冷却、审计、撤销（`internal/actionreceipt`、`internal/controlplane/actions.go`） |
| 工单无审批 | 案件状态机 + 审批绑定（`internal/policy/session_approval.go`、`CaseDetailsPage`） |
| 设备/账号身份区间 | `internal/store/identity.go`、`internal/legacy4k`、`cmd/legacy-4k-identity-bridge` |
| 4K 集成 | `internal/legacy4k`、`internal/productpolicy`、`docs/integrations/srun4k.md`、迁移 `072`–`091` |

**一处需要注意的策略能力差异（不是缺口，但影响现场切换）**：旧系统在南昌以 `--policy-shadow-mode=false` **真实执行**过设备数量触发的下线/降速/封禁；当前系统对 `shared_access` 与 `explicit_proxy` 两个 trigger **禁止 `automatic` 模式**（`internal/policy/engine.go:80-85`，报 `proxy protocol evidence supports observe or manual mode only` / `shared access supports observe or manual mode until detection and control gates are verified`），只有 `quota_exceeded` 与 `session_quota_exceeded` 允许自动。因此"设备数量超限自动处置"可平移，"共享接入/显式代理自动处置"当前被刻意闸住，需按现场验收门槛单独决策。

## 四、旧系统内已不可达（不建议对齐）

以下能力在南昌分支**没有生产调用方**，不要为对齐而补：

| 旧能力 | 不可达证据 | 当前替代 |
|---|---|---|
| License 授权强制 | `cmd/server/capture.go:178-181` 校验被注释；仅 `PUT /api/license` 调用 | 商业策略，单独决策 |
| 告警策略执行 | `pkg/devices/proxy.go:324` `alert.Engine.Check` 被注释；`alert.Setup` 虽执行但无判定消费方 | 由 G10 重新设计 |
| 准入策略引擎 | `cmd/server/capture.go:402` `access.Setup()` 被注释 | 策略 `Scope` + 黑名单（G02） |
| GeoIP 归属 | `internal/analyze/analyze_multi.go:273` maxmind 调用被注释（`maxmind.Setup` 仅加载） | 如需再评估 |
| 日志备份/恢复 | `internal/web/router/router.go` backup 组整体注释；`pkg/task` 引用不存在的包 | 部署层备份（`docs/openeuler-one-click-deployment.md`） |
| CAPWAP 解码 | `internal/analyze/handle/capwap.go` 只打印 stdout，无调用方 | 无需求 |
| 自研 LLMNR/NBNS 解码 | `pkg/layers_handle/**` 未被 import；`docs/nanchang-protocol-regression-20260907.md:53` 明确"未接入正向识别器" | Zeek `nbns.log` / `llmnr.log` 已接入（`legacy-essentials-implementation.md` T07） |
| RBAC 接口鉴权 | `pkg/manager/impl.go:397` `CheckInterfaceAuthority` 零调用方；权限只经登录响应交给前端做页面级控制 | 当前强制 `rolePermissions` + 每路由 `requiredPermission` |
| 端口熵阈值 | `pkg/capture/classifier/setup.go:28` `EnableEntropy:false` | 无需求 |
| 打印机 WebSocket | `internal/web/router/router.go:30-33` 整组注释，且注释引用了不存在的 `websockets.List()`；`websockets` 包无调用方 | 无需求 |
| 声明式条件求值器 | `third_party/antipolicy/condition` 整包零 import；`timer_set_id` 分支仍是 TODO 且恒 false | 策略 `Scope` 已覆盖 |
| socket 空处理器 | `MessageEngine`(=17) 空实现（`internal/socket/handler/message.go:11-13`）；`NorthboundInterface`(=15) 函数体为空（`handler/interface.go:56-58`）；`PrinterDevices`(=8) 未注册 handler，客户端收到 `Unknown message type` | 无需求 |
| 孤儿包 | `pkg/layers_handle`（含 llmnr/nbns）、`pkg/component/mac_oui`、`pkg/component/pprof` 三个包无任何 import | 无需求 |
| 加密/鉴权弱点 | JWT 密钥硬编码（`internal/web/midderware/auth.go:10`）、密码明文存储与比对（`pkg/manager/impl.go:165-167`）、SM4 密钥/IV 硬编码并打印到 stdout（`internal/web/controllers/sso.go:43-64`）、北向 token 无过期 | 当前为 OIDC + 哈希口令 + 强制 RBAC + 会话失效 |

**补充：旧系统在检测侧也已落后的点**（不需要对齐）——旧系统**没有** SNMP 探测/路由器发现（`internal/analyze/udp.go` 只做 161 端口计数，`decodeSNMP` 为空实现，依赖里也没有 SNMP 库），**没有** OIDC，**没有** `/readyz`/`/healthz` 健康检查；DHCP option 55 只拼成弱证据字符串、无指纹库匹配；JA3 只采集落库、不做聚类分析；LLMNR/NBNS 采集入口与识别器都未接线。当前系统在这些点上均更强。

**注**：南昌分支已把基础版中"不可达"的若干项接回生产链路——`whitelist.Setup`（`capture.go:412`）、`blacklist.Setup`（`:415`）、`iprange.Setup`（`:409`，`users.ExitsUser` 在 `internal/analyze/factory.go:49`、`analyze_multi.go:355` 实时调用）、`northbound.Setup`（`:399`）、`behavior.Setup`（`:372`）均**在用**。旧文档基于基础版的"不可达"判断对这几项已失效。

## 五、建议补齐顺序

> 可执行清单见 `docs/legacy-feature-gap-ncu-backlog.md`（含 G01–G16 逐项核对结论、落点、迁移、验收、测试与风险）。本节只给顺序结论。

1. **G01 通知发送方**（出箱消费者 + 通道 + 模板/参数映射 + 重试与状态回写 + 测试发送）——出箱表与 `notify` stage 已就位，这是最短路径；其余处置策略的运营前置能力。
2. **G03 + G04 投毒行为检测与网络安全行为北向上报**——南昌现场对外集成承诺，依赖最少、外部可见度最高。
3. **G02 黑名单准入**、**G06 动作级时段**——补齐名单与时段两个策略维度。
4. **G05 仅路由器用户发送**——G01 完成后的小改动。
5. **G07 AI 中转站审计台账**、**G08/G09 补充信号**——先回放测试再接真实流量。
6. **G10 监控告警**，**G11–G16** 按现场需求排期。

## 六、附：核对中发现的代码级问题（不影响"缺哪些功能"的结论，但影响判定可信度）

以下三项均在本次核对中直接读代码确认，与旧能力对比无关，但会削弱上面几项结论的可靠性：

1. **`notification_outbox` 只写不读**（见 G01）：全仓唯一引用是 `internal/controlplane/native_dispatch.go:139` 的 INSERT；`status` 永远是 `queued`，写入后动作即被标记 `succeeded`。也就是说"通知已入队"被当作"通知已发送"。
2. **`shared_device_divergence` 是不可达分支**：`internal/risk/risk.go` 的 `detectionBasis`（`:670-707`）只会返回 `explicit_tunnel` 或 `behavioral_only`，从不返回 `shared_device_divergence`；而 `levelFor`（`:464`）、`combinedConfidence`（`:275`）、`automationAssessment`（`:323`）、`combinedScore`（`:431`）以及 `internal/controlplane/risk_action_validation.go:71` 都在判断该值。此外 `levelFor` 检查的组名是 `identity_access` / `identity_mac`，而 `detectionBasis` 实际产出的是 `identity_access_reference` / `identity_mac_reference`（`:687-689`），两者永不相等。结论："IP 风险路径下由共享设备分歧升级为 confirmed" 这条逻辑当前不可达；共享接入的确认状态实际由 `internal/sharedaccess` 独立承担。需确认这是重构遗留还是有意收口。
3. **标准事件 schema 与产出漂移**：`schemas/normalized-event-v1.schema.json:29-41` 的 `type` 枚举只有 `flow/dns/tls/http/quic/device/identity/alert/discovery`，但适配层产出 `proxy_transaction`（`internal/adapter/suricata/proxy.go:20`、`internal/adapter/zeek/proxy.go:31`）；`flow.direction` 枚举为 `outbound/inbound/unknown/internal`，但 `internal/adapter/zeek/adapter.go:199` 产出 `management`。若下游按 schema 校验会拒绝这些事件。

## 七、局限

- 本文基于两侧代码静态调用链与构建产物（旧系统前端已提取路由表）判断，未在南昌现场运行验证；旧系统运行时依赖（MongoDB / Redis / ES / Grafana）不在本机。
- 旧系统 `third_party/antipolicy` 的"多动作 + depends_on + duration/interval/trigger_count"升级语义，当前用顺序 stage 近似；若现场确有等价需求，需逐条核对转换，不能直接照搬阈值。
- 旧系统身份来源是外部 AAA 的 Redis 在线表，当前走 4K 桥与 SRun API；现场切换等价性需单独验证，本文不覆盖。
- 提交 `364ec17`（路由器数量条件）标注"尚未部署现场"，其现场可用性未在本文核实。
