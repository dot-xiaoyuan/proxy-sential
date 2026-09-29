# 旧防代理系统（dpi-analyze）能力差距分析

本文对比旧系统 `/Users/yuantong/Developer/Projects/golang/dpi-analyze` 与当前 `proxy-sentinel`，回答**当前系统还缺哪些核心功能**，并区分"旧系统真实在用""旧系统只有配置/代码但未执行""纯架构差异"三类。

结论先行：**检测与风险判定层面，当前系统已经整体超过旧系统的可用能力；真实核心缺口集中在"用户消息通知"一处，以及少量信号（路由器置信度、端口聚类、协议频次）和运维可视化。** 旧系统管理面有大量功能是"配了但没执行"，不能直接当成待补清单。

## 一、对比口径

- 旧系统：276 个 Go 文件、约 3.4 万行；capture + web 双进程，Unix socket 通信；存储 MongoDB / Redis / Elasticsearch。
- 当前系统：404 个 Go 文件、约 7.1 万行；采集交给 Suricata/Zeek，存储 PostgreSQL / ClickHouse。
- **判定标准**：一个旧能力只有存在生产调用链才算"在用"。有类型、控制器或配置、但无调用方的，归入"不可达"，不计为缺口。

## 二、旧系统真实在用、当前缺失的核心功能

### P0 用户消息通知子系统（模板 + 通道 + 队列 + 测试发送）

这是当前最实的一块缺口。旧系统的通知链路是**完整且已启动**的：

- 启动装配：`cmd/server/capture.go:421` `message.Setup()`、`:424` `strategy.Setup()`、`:453` `company.Setup()`、`:456` `company.Engine.Listen()`；`pkg/component/policy/strategy/strategy.go:66` 内 `go e.Listen()` 消费发送通道。
- 投递路径：`strategy.Engine.Push` → 通道（cap 100）→ `RPush list:message:dispatcher`（`strategy.go:140-166`）→ message-engine dispatcher → SRun provider。
- 短信通道：`pkg/sms/company/supwisdom.go`（Supwisdom OAuth2 client-credentials）；`pkg/sms/sender.go` 定义发送接口。
- 模板 CRUD API：`internal/web/controllers/policy.go:829-894`（`GET/POST /api/policy/message`、`PUT/DELETE /api/policy/message/:id`、`GET/PUT /api/policy/message/information`）。
- 短信通道配置与**发送测试**：`internal/web/controllers/policy.go:600`（`POST/GET /api/policy/information`、`PUT /api/policy/information/:id`、`POST /api/policy/information/test`）。
- 模板持久化：`$DPI_HOME/etc/template.json`；模板变量样例见 `pkg/sms/company/README.md`（username / account / ip / mac / brand / name / student_id / contact_number / date）。
- 动作侧：`third_party/antipolicy/action/builtin/msg_notify.go`，执行在 `pkg/devices/register.go:125` `strategy.Engine.Push(input, template, user.GetVariable())`。

当前系统的对应能力只有：策略 stage 的 `Template string`（`internal/policy/engine.go:31`），原样透传给连接器（`internal/controlplane/policy_actions.go:285`）。**没有模板存储与变量渲染、没有站内/短信通道、没有投递队列与重试、没有测试发送、没有送达状态。** 这意味着"先通知教育、再升级处置"这条运营闭环目前接不上。

### P0 私接路由器识别置信度与"路由增量"策略条件

- 旧系统 `pkg/devices/router_confidence.go:86-183` `CalculateRouterConfidence`：MAC OUI 路由器品牌 +60、设备类型 router +15、TTL 64–128 +5、设备名关键词 +10、HTTP Host/SNI 路由器管理域关键词 +12、多源确认额外 +5/+5，0–100。该方法**在用**，调用点 `pkg/devices/merge.go:352,434,472,522`。
- 策略条件：`third_party/antipolicy/strategy/model.go` `Condition.RouteIncrease` + `engine/evaluator.go:100` `in.IsRouted && cond.RouteIncrease`；输入侧 `types.PolicyInput.IsRouted / ConfirmedRouter / RouterConfidence`。

当前系统：`internal/policy/identity.go:133-137` 的 `Limits` 只有 Total/Mobile/PC，**没有 routed 维度**；发现模块能把设备标成 router（`internal/discovery/model.go:152,188`），但不进入风险与策略。**缺少"确认路由器"这一独立信号与对应策略条件。**

### P1 源端口聚类的共享设备信号

旧系统用源端口递增规律推断"同一 IP 后面有几台设备"：`pkg/capture/classifier/classifier_new.go:212-313`（递增间隔聚类，动态阈值 `avgTrend*1.5+10`、最少 20 端口、2–3 簇、跨度 >1000），产出见 `pkg/capture/resolve/port.go:9-25`，由 `config.EnableCluster` 开启、`internal/analyze/reader.go` 喂数据。

当前系统的共享判定只用 UA/OS、TTL、TLS 栈、DHCP 画像四类多样性（`internal/sharedaccess/evaluate.go:203-221`），**没有端口形态这一独立信号组**。属于可加的补充证据，不是阻塞项。

### P1 按协议的观测频次异常（疑似记录）

旧系统对每个 IP 的协议观测计数，超阈值落"疑似"：`pkg/capture/member/ip_feature.go:47-116`、`ip_suspected.go:42-116`，阈值来自 `dpi.yaml thresholds.*`（SNI/HTTP/TLSVersion/CipherSuite/DNS/QUIC/SNMP/Session，默认 200），写 Mongo `suspected`，并有 `GET /api/feature/judge/suspected` 查询页。

当前系统只有粗粒度替代：`domain_diversity`（≥20 个不同域名，分数上限 25）和 `port_distribution`（≥5 个目的端口）。**缺少按协议可配置阈值和独立的"疑似"清单。**

### P1 监控可视化与告警回调

旧系统有完整的监控面：Prometheus exporter（`cmd/server/capture.go:499-502`，含 capture/flow/drop/device/proxy/AAA/协议等大量指标族）、Grafana 反向代理（`internal/web/router/router.go` `api.Any("/grafana/*proxyPath")`）、Grafana 告警 webhook 入库（`POST /api/webhook` → `internal/web/controllers/grafana.go:19-34`）、报告查询（`GET /api/monitor/report`）。

当前系统只有 Prometheus `/metrics`（`internal/controlplane/server.go:446`），**没有仪表盘、没有告警回调面、指标族也少得多**。属于运维缺口。

### P2 设备事件南向推送（IDevM）

旧系统把发现的终端事件推给外部设备管理平台：`pkg/events/idevm/`（`RedisPusher` 把 `DeviceEvent` RPush 到远端 Redis 队列，密码 AES 解密），由 `interface.southbound` 配置驱动（`GET|PUT /api/southbound`），默认关闭。当前系统**没有等价的外部设备事件流**（`southbound` 零命中）。现场若依赖该集成需要补。

### P2 运营便利项

- **本地用户组管理**：旧系统有管理员/用户组两套 CRUD（`pkg/manager`，Mongo `manager.user` / `manager.user_group`）。
- **用户自助改密**：旧系统 `POST /api/change-password`。
- **Prometheus 指标导出为 Excel**：旧系统 `GET /api/export/excel` 查询 Prometheus `query_range` 生成 xlsx（`internal/web/controllers/export.go:34-143`）。

当前系统是固定角色 viewer/reviewer/operator/admin（`internal/controlplane/security.go:211-223`），用户增改由管理员执行（`internal/controlplane/users.go`），导出只有 CSV。注意当前系统的 CSV 数据导出（风险/证据/案件/审计）在业务上强于旧系统的"指标导出"，所以这里只是便利性差异。

## 三、旧系统只有配置/代码、实际未执行（不要照搬为缺口）

以下能力在旧系统里"看起来有"，但生产链路不可达或未启用。**当前系统不应为了对齐它们而补功能**；其中若干项当前系统反而做得更严（见第四节）。

| 能力 | 旧系统落点 | 不可达证据 |
|---|---|---|
| License 授权强制 | `pkg/component/license/license.go:16-68` | capture 启动校验被注释 `cmd/server/capture.go:182-185`；仅 `PUT /api/license` 调用；无中间件拦截 |
| 告警策略执行 | `pkg/component/policy/alert/alert.go:111-160` | `alert.Engine.Check` 零调用方；`load()` 还有 nil-map 写入隐患 |
| RBAC 接口鉴权 | `pkg/manager/impl.go:397-425` | `CheckInterfaceAuthority` 零调用方，`PAGE_ACTION_*` 未使用；任意登录用户可调任意接口；管理员密码明文比较 |
| 入站北向接口授权 | `pkg/nb_interface`、`/api/nbinterface/*` | `NBAuthority` 的 token/IP 无任何校验消费方；`gen-token` 签发无过期 JWT |
| 准入策略引擎 | `pkg/component/policy/access` | `access.Setup()` 被注释 `cmd/server/capture.go:433-435`，`getStrategy` 亦被注释；`PolicyAccess` IPC 还 nil 解引用 |
| 区域策略执行 | `pkg/component/policy/iprange` | 唯一消费者 `users.ExitsUser` 零调用方；`CheckIP` 恒返回空 CIDR，IPv6 为桩 |
| 降速动作 | `third_party/antipolicy/action/builtin/bandwidth_reduction.go`、`GET|POST /api/policy/slow-down` | `config.Cfg.SlowDown/BindWidth` 无消费方；该动作走通用分支，不施加任何限速 |
| 工单审批流 | `POST /api/work_order`、`/api/policy/work_order*` | 类型只有 content/created_at，无状态机、无审批人，只是留言板 |
| 流量集中度代理启发式 | `pkg/capture/aggregator/aggregator.go` | `AddFlowKey` 唯一调用点在 `analyze_multi.go:438` 被注释，永远返回 false |
| 日志备份/恢复 | `internal/web/router/router.go` backup 组 | 路由整体注释；`pkg/task` 还 import 了不存在的 `internal/db/backup`（`build_err.txt`） |
| CAPWAP 解码 | `internal/analyze/handle/capwap.go` | 只打印 stdout，无调用方 |
| 自研 LLMNR/NBNS 解码 | `pkg/layers_handle/**` | 整个包未被 import |
| JA3 行为图共享判定 | `pkg/capture/resolve/ja3.go` | `IsShared` 零调用方 |
| GeoIP 归属 | `pkg/component/maxmind` | 唯一使用点在 `analyze_multi.go:244-247` 被注释 |
| 端口熵阈值 | `pkg/capture/classifier/setup.go:26-31` | `EnableEntropy:false` |
| brands_root 品牌根域 | `pkg/parser/brands.go:12` | YAML 用 `domain:`，解析器读 `domain_name`，匹配恒为空 |
| 打印机 WebSocket | `internal/web/websockets/printer.go` | 路由注释，且无 `PrinterDevices` socket handler |

## 四、当前系统已经领先旧系统的能力

这些是旧系统**完全没有**或明显弱于当前的，不属于缺口：

- **隧道/代理协议识别**：WireGuard / OpenVPN 高置信签名、HTTP CONNECT / SOCKS5 `proxy_transaction`、代理域名情报、AI 中转站指标（`internal/airelay`）。旧系统没有任何 VPN 协议指纹。
- **证据化与风险分级**：独立信号组、分数/置信度/窗口/解释、自动化资格门槛（`internal/evidence`、`internal/risk`）。旧系统只是设备计数过阈值。
- **共享接入独立模型**：覆盖率、身份会话绑定、冲突判定（`internal/sharedaccess`）；旧系统只有计数。
- **处置连接器抽象**：HMAC / 4K 原生、影子准入、熔断、回执校验、幂等、撤销（`internal/controlplane/actions*.go`、`internal/actionreceipt`）。旧系统是进程内直调 Redis/SRun，且无回执校验。
- **身份与权限**：真实 OIDC（旧系统只有手写 SM4 门户跳转，且把密钥打到 stdout）、强制 RBAC、审计日志、异步导出、SNMP 主被动发现、域名生态、指纹离线包。
- **工单/审批**：当前有案件状态机与审批绑定；旧系统工单无审批流。
- **存储与规模**：ClickHouse 明细查询、服务端分页与性能验收。

## 五、架构差异（不是缺口）

| 维度 | 旧系统 | 当前系统 |
|---|---|---|
| 采集 | 自研 AF_PACKET + gopacket TCP 重组 | Suricata / Zeek 适配为标准事件 |
| 存储 | MongoDB / Redis / Elasticsearch | PostgreSQL / ClickHouse |
| 进程模型 | capture + web 双进程，Unix socket IPC | systemd 多进程（ingest / controlplane / worker） |
| 守护 | go-daemon CLI（start/stop/restart/ps） | systemd |
| 策略下发 | 写 Mongo 后 socket 通知 capture 重载内存引擎 | 数据库版本 + 重算/物化 |
| 规则热更新 | 进程内 matcher 重建（`PUT /api/feature/library`） | 版本化离线指纹包 + 后台回填 |

## 六、建议补齐顺序

1. **消息通知子系统**（P0）：模板 CRUD + 变量渲染 + 通道配置 + 投递队列与重试 + 测试发送。落点建议 `internal/notify`（模板与通道抽象），新增模板/通道/测试接口；策略 stage 的 `template` 从字符串升级为模板 ID。必须保留影子模式与审计。
2. **路由器置信度与 routed 策略条件**（P0）：把设备识别结果中的路由器品牌/类型/管理域关键词做成独立证据，并在 `internal/policy` 增加 routed 维度。
3. **协议频次阈值 + 端口聚类信号**（P1）：作为共享接入/风险的补充独立信号组，先写回放测试再接真实流量。
4. **监控报表与告警回调**（P1）：在现有 `/metrics` 之上补仪表盘与告警 webhook，或明确由外部 Grafana 抓取。
5. **南向设备事件与运营便利项**（P2）：IDevM 类外部设备事件流、本地用户组、自助改密，按现场集成需求排期。

## 七、局限

- 本文基于代码静态调用链判断"在用/不可达"，未在旧系统现场运行验证；旧系统的运行时依赖（Redis/Mongo/ES/AAA/Grafana）不在本机。
- 旧系统 `third_party/antipolicy` 的"多动作 + depends_on + duration/interval/trigger_count"升级语义当前用顺序 stage 近似；若现场确有等价需求，需逐条核对转换，不能直接照搬阈值。
- 旧系统的身份来源是外部 AAA 的 Redis 在线表（`list:rad_online` / `hash:rad_online:*`），当前系统走 4K 桥与 SRun API。现场切换时需单独验证等价性，本文不覆盖。
