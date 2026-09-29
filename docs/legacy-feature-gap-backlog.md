# 旧系统能力补齐清单（按优先级）

基于 `docs/legacy-feature-gap.md` 的差距分析，把待补功能整理成可执行清单。每条包含**验收标准、落点、依赖与风险**，并遵守项目既有约束：先写回放测试再接真实流量；新增风险规则必须返回证据/分数/置信度/窗口/解释；处罚动作必须支持影子模式、冷却、审计与人工撤销；不在热路径做阻塞落库。

## 汇总

| ID | 优先级 | 功能 | 规模 | 阻塞关系 |
|---|---|---|---|---|
| N01 | P0 | 用户消息通知子系统 | L（可拆 5 步） | 无 |
| R01 | P0 | 路由器置信度 + routed 策略条件 | M | 依赖 N01 才能完整闭环（先通知后处置） |
| S01 | P1 | 端口聚类共享设备信号 | M | 无 |
| S02 | P1 | 协议频次阈值与"疑似"清单 | M | 无 |
| O01 | P1 | 监控指标补齐 + 告警回调 + 仪表盘 | M | 无 |
| I01 | P2 | 设备事件南向推送（IDevM 类） | M | 需现场确认外部平台协议 |
| U01 | P2 | 本地用户组管理 | S | 无 |
| U02 | P2 | 用户自助改密 | S | 无 |
| X01 | P2 | 指标导出为 Excel | S | 低价值，可延后 |

命名约定：PostgreSQL 迁移从 `059` 起，ClickHouse 从 `017` 起（当前最新 `058` / `016`）。

---

## P0

### N01 用户消息通知子系统

**为什么**：当前策略只有 `Stage.Template string`（`internal/policy/engine.go:31`）原样透传给连接器（`internal/controlplane/policy_actions.go:285`），缺"先通知教育、再升级处置"的运营闭环。

- [ ] **N01a 通知模板存储与变量渲染**
  - 验收：模板可创建/查询/更新/删除；支持变量占位渲染；渲染失败有明确错误；渲染不执行任意表达式（只做白名单变量替换）。
  - 落点：新增 `internal/notify`（模板模型 + 校验 + 渲染）；迁移 `059_notifications.sql`（`notification_templates`）；控制面路由 `/api/v1/notifications/templates`。
  - 变量至少覆盖：账号、IP、MAC、设备品牌/型号、策略名、证据摘要、时间、联系人。
- [ ] **N01b 发送通道配置**
  - 验收：通道可配置且密钥加密存储；至少支持通用 webhook；SMTP/短信作为可插拔 provider，未配置时明确不可用而不是静默失败。
  - 落点：`internal/notify` provider 接口 + `notification_channels` 表；密钥沿用现有主密钥加密方式（对齐 `internal/controlplane/actions.go` 的 connector secret 处理）。
- [ ] **N01c 投递队列、重试与送达状态**
  - 验收：投递异步、失败按退避重试并封顶；有 `pending/sent/failed` 状态与最后错误；**投递入队不等于送达**，状态需区分 queued 与 delivered/confirmed。
  - 落点：`internal/notify` 队列 + `notification_deliveries` 表；复用 `internal/realtime` 的告警发送模式或控制面后台 worker。
  - 风险：不得在风险热路径同步发送；必须走队列。
- [ ] **N01d 测试发送 + 管理接口 + 页面**
  - 验收：可对指定账号/手机号做测试发送；页面在系统管理下新增"通知模板/通道"；三视口（390/1280/1440）通过检查；遵守缺省值展示规范（空值不显示占位符）。
  - 落点：`POST /api/v1/notifications/test`；`frontend/src/pages` 新增页面 + `frontend/src/app/AppShell.tsx` 导航项 + `router.tsx`。
- [ ] **N01e 策略接入**
  - 验收：`Stage.Template` 从"任意字符串"收敛为模板 ID 并保持向后兼容（旧值仍可透传）；`notify` stage 经 N01c 队列投递；执行记录写入审计。
  - 落点：`internal/policy/engine.go` `Stage`、`internal/controlplane/policy_actions.go:215` notify 分支。
  - 风险：模板校验属于策略校验（`Definition.Validate`），需补单测。

### R01 路由器置信度 + routed 策略条件

**为什么**：旧系统有在用的路由器识别打分（`pkg/devices/router_confidence.go:86-183`，调用点 `merge.go:352,434,472,522`）和 `route_increase` 策略条件；当前 `Limits` 只有 Total/Mobile/PC（`internal/policy/identity.go:133-137`）。

- [ ] **R01a 路由器证据**
  - 验收：产出独立证据类型（建议 `confirmed_router`），带分数/置信度/窗口/解释/样本；来源至少覆盖 MAC OUI 品牌、设备类型 router、设备名关键词、HTTP Host/SNI 路由器管理域；多源命中提升置信度。
  - 落点：`internal/evidence/evidence.go` 新增信号与证据；路由器品牌/关键词表放可维护资产（对齐 `internal/fingerprint/data/` 的版本化做法）。
  - 风险：**不得把普通网关/基础设施误判为用户私接路由器**；需用 `isInfrastructureRole` 类似机制排除；先写正反例回放 fixture。
- [ ] **R01b routed 策略条件**
  - 验收：策略可按"存在确认路由器"触发；与现有 `quota_exceeded / shared_access / explicit_proxy` 并列；未启用时行为不变。
  - 落点：`internal/policy/engine.go` `Limits` 或 `Scope` 增加 routed 维度 + `Validate` + `internal/controlplane/policy_actions.go` 取值。
- [ ] **R01c 回放测试**
  - 验收：新增 `examples/replay/router-*.jsonl`，覆盖私接路由器正例、校园网关反例、仅 UA 关键词的弱例。

---

## P1

### S01 端口聚类共享设备信号

**为什么**：旧系统用源端口递增规律判断"同一 IP 后有几台设备"（`pkg/capture/classifier/classifier_new.go:212-313`）；当前共享判定只有 UA/OS、TTL、TLS 栈、DHCP 画像四类（`internal/sharedaccess/evaluate.go:203-221`）。

- [ ] 验收：新增第五类独立信号组（端口形态），进入 `sharedaccess` 判定；满足现有"重复共现"要求（`repeatedTogether`），不能单靠该信号定性；有正反例回放。
- 落点：`internal/evidence`（端口序列聚类）+ `internal/sharedaccess/evaluate.go`（新增信号组与 `Window` 字段）。
- 风险：NAT/CGNAT 与端口复用会造成误报；阈值需现场标定，默认应偏保守。

### S02 协议频次阈值与"疑似"清单

**为什么**：旧系统按协议统计观测次数超阈值即落"疑似"（`pkg/capture/member/ip_feature.go:47-116`、`ip_suspected.go:42-116`，阈值可在 `dpi.yaml` 配置）；当前只有 `domain_diversity`（≥20 域名）和 `port_distribution`（≥5 端口）这类固定粗粒度替代。

- [ ] 验收：按协议（SNI/HTTP/TLS 版本/加密套件/DNS/QUIC/Session）可配置阈值；超阈值产出证据并可查询"疑似"清单；阈值变更不影响历史结论。
- 落点：`internal/evidence`（新证据类型）+ 规则配置存储 + 控制面查询接口 + 前端列表页。
- 风险：与 `domain_diversity` 语义重叠，需明确层级，避免同一现象重复计分。

### O01 监控指标补齐 + 告警回调 + 仪表盘

**为什么**：当前 `/metrics` 只有 ready/ingest/application/identity 指标族（`internal/controlplane/health.go:20-65`）；旧系统有 Grafana 反代、告警 webhook 入库与报告页，指标族也丰富得多。

- [ ] **O01a 指标族补齐**
  - 验收：新增风险快照、证据、案件、策略执行、处置动作、共享接入的 Prometheus 指标；命名统一前缀 `proxy_sentinel_`。
  - 落点：`internal/controlplane/health.go` `handleMetrics` 拆分与扩展。
- [ ] **O01b 告警规则 + webhook 回调**
  - 验收：可配置阈值与静默窗口，触发时回调 webhook；复用 `internal/realtime/worker.go` 的 `sendAlert` 模式；告警本身写审计。
  - 落点：控制面新增告警规则存储 + 后台评估 worker。
- [ ] **O01c 仪表盘**
  - 验收：要么在 `frontend` 内提供运营仪表盘页，要么在 `docs` 明确由外部 Grafana 抓取 `/metrics` 并给出面板清单。二选一必须明确，不能悬空。

---

## P2

### I01 设备事件南向推送（IDevM 类）

- [ ] 验收：可配置外部目标与队列，把终端发现/变更事件异步推送；默认关闭；失败有重试与状态；密钥加密存储。
- 落点：新增 `internal/southbound`；`cmd/discovery-worker` 或独立 worker；控制面配置接口。
- 依赖：**需现场确认外部设备管理平台的协议与鉴权**，否则只做通用 webhook 形态。

### U01 本地用户组管理

- [ ] 验收：可创建用户组、分配角色与权限；组内用户继承权限；与现有 `rolePermissions`（`internal/controlplane/security.go:211-223`）兼容。
- 落点：迁移新增 `user_groups` 表 + `internal/controlplane/users.go` + 前端设置页。
- 说明：旧系统的用户组是**未强制**的元数据（`CheckInterfaceAuthority` 零调用方），因此这里只做管理便利，不改变现有强制鉴权模型。

### U02 用户自助改密

- [ ] 验收：登录用户可改自己的密码；需校验原密码；改密写审计；不开放修改他人密码与角色。
- 落点：`internal/controlplane/security.go` + 路由 `/api/v1/auth/password`。

### X01 指标导出为 Excel

- [ ] 验收：可选。当前 CSV 异步导出（`internal/controlplane/exports.go`）已覆盖业务数据导出；仅当现场明确要求 xlsx 时再做。
- 说明：旧系统的 `GET /api/export/excel` 实际只是把 Prometheus 查询结果导出为 xlsx（`internal/web/controllers/export.go:34-143`），业务价值低于当前 CSV 导出。

---

## 明确不建议补（旧系统"配了但没执行"）

以下能力在旧系统生产链路不可达，且当前系统在对应领域更严；**不要为了对齐而补**：

| 旧能力 | 不可达证据 | 当前替代 |
|---|---|---|
| License 授权强制 | capture 启动校验被注释 `cmd/server/capture.go:182-185` | 授权属商业策略，单独决策 |
| 告警策略执行 | `alert.Engine.Check` 零调用方 | 由 O01b 重新设计 |
| RBAC 接口鉴权 | `manager/impl.go:397-425` 零调用方 | 当前已强制 `rolePermissions` |
| 入站北向授权校验 | `pkg/nb_interface` token/IP 无消费方 | 出站连接器 + HMAC 回调（`internal/actionreceipt`） |
| 准入策略 / 区域策略执行 | `access.Setup()` 被注释；`ExitsUser` 零调用方 | `internal/policy` Scope（校区/VLAN/CIDR/时段） |
| 降速动作 | `config.Cfg.SlowDown` 无消费方 | `rate_limit` stage（`RateKbps`/`DurationSeconds`） |
| 工单审批流 | 旧工单无状态机、无审批人 | 案件 + 审批绑定（`internal/policy/session_approval.go`） |
| 日志备份/恢复 | 路由注释 + `pkg/task` 引用不存在的包 | 部署层备份（`docs/openeuler-one-click-deployment.md`） |

---

## 建议执行顺序

1. **N01a → N01c**：先把通知的"模板 + 队列"立起来，这是其他所有处置策略的前置运营能力。
2. **R01a → R01c**：路由器证据与策略条件，补齐防代理的核心判定维度。
3. **N01d/N01e**：通知接入策略与页面，形成"通知→降速→下线"分级闭环。
4. **S01、S02**：补独立信号组，提升共享接入与疑似的召回（先回放、再真实流量）。
5. **O01**：监控与告警，保障前四项上线后可观测。
6. **P2 各项**按现场集成需求排期。

## 通用完成定义（DoD）

- 新增采集/派生信号：先适配标准事件，风险引擎不得读取后端原始字段。
- 新增证据：必须返回证据、分数、置信度、窗口和解释文本，并带样本。
- 新增动作：必须支持影子模式、冷却、审计日志与人工撤销。
- 先有回放 fixture 与 Go 测试，再考虑真实流量。
- 前端改动：`npx tsc --noEmit` 与生产构建通过；三视口检查；遵守缺省值与对比度规范。
