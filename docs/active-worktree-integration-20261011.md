# 活跃工作区集成记录（2026-10-11）

本文记录把当时活跃的 5 个工作区改动合并到一条集成分支的过程、功能清单、逐个冲突的取舍依据与验证结论，供后续复核与继续集成。

- **集成分支**：`codex/integration-all-20261011`
- **worktree**：`.worktrees/integration-all-20261011`
- **基线**：`main`（`a2d43a4`）
- **规模**：相对 `main` 共 54 个提交、674 个文件、+71133 / −9300
- **原则**：现有 5 条分支与各自工作区保持不动；集成只发生在新分支上，可整条丢弃重来

## 一、合并状态

| 来源 | 提交数 | 状态 |
|---|---|---|
| `codex/menu-function-repair-20260930`（含本轮 NCU 缺口 P0） | 16 | 已并入 |
| 主工作区另一会话未提交的「链路层 MAC 归属」工作区状态 | 1 笔（`dcc5acc`） | 已并入 |
| `codex/local-zeek-replay` | 21 | 已并入 |
| `codex/shared-device-profile` | 15 | 已并入 |
| `codex/ieee1905-passive` | 24 | 已并入 |
| `codex/shared-risk-only` | 3 个独有提交 | **未并入**，理由见第五节 |

## 二、功能改动清单

### 1. NCU 缺口 P0（提交 `2493abb`）

- **通知发送方**：迁移 `092_notification_delivery.sql`；`internal/notify`（模板白名单变量渲染、通用 HTTP 通道、可插拔 OAuth2 短信通道、退避）；`internal/controlplane/notifications.go`（模板/通道/出箱接口 + 10s 投递 worker + 测试发送）；策略 `Stage.ChannelID`。**解析不到通道时直接记 `failed`，不再静默 `queued`。**
- **黑名单准入**：`internal/policy/blacklist.go`；`whitelistManager` 泛化为双名单管理器（同一 revision/审计/校验语义）；新增 `blacklist_hit` 触发维度。名单读取失败时 `Input.Known=false`，不误动作也不误恢复；白名单优先级保留。
- **内网目标访问检测**（旧「投毒行为」）：迁移 `093_destination_targets.sql`；纯函数包 `internal/poison`（可回放、可试算）；ClickHouse 聚合查询；60s worker；`internal_target_access` 弱证据（封顶 30 分、不单独升级）；正反例回放 fixture。**规则默认关闭，网段与阈值由现场提供。**
- **网络安全行为北向上报**：迁移 `094_behavior_reports.sql`；`internal/behaviorreport`（令牌获取、批量、字段映射、4xx 不重试）；15s worker；消费投毒/代理/AI 中转三类证据。**通道默认关闭，平台契约待现场确认。**

### 2. 链路层 MAC 归属与被动设备普查（`dcc5acc`）

- **协议自报归属**：HTTP Server 头、TLS 证书主体/签发者/SAN、JA3/JA4 经唯一 DHCP 租约归属到设备；派生事件只写 PostgreSQL，不回写 ClickHouse 标准事件，因此不影响证据聚合、风险评分、共享接入与路由器识别。
- **`device-census` 只读普查命令**：输出镜像可见设备（MAC、源地址、持有效租约数）与已识别画像覆盖。
- **终端画像页**：新增「链路层归属（近 24 小时）」区块与按来源可见性列表；无 MAC 归属时提示 Zeek 需加载 `mac-logging`。
- 部署脚本启用 Zeek `mac-logging`；`examples/replay/device-mac-attribution.jsonl`。

### 3. 被动设备发现（`codex/ieee1905-passive`）

- **采集**：IEEE 1905.1/EasyMesh 客户关联（含拓扑快照、AL MAC 判定）、mDNS PTR/SRV/A/AAAA、ARP、IPv6 NDP、SSDP、**WS-Discovery**、CDP/LLDP/VRRP/HSRP。
- **物化**：`discovery_observation_latest` 投影表（撤回与未来报文正确处理）、绑定查询索引、批量事务、超时与积压治理、快照缓存。
- **呈现**：地址族与作用域、历史地址、设备分类与能力 facet、多协议地址归并、mDNS 查询过滤。

### 4. 共享设备档案（`codex/shared-device-profile` 与基线）

- 物化持久化、并发提至 8 worker、高频任务排队修复、认证历史索引查询优化、发布后采集服务恢复修复。
- 共享行为专用风险链路：`risk_kind`（`shared_access` / `router_observation`，由 `riskKindForRuleset` 统一映射）。
- 共享行为锚点：`ieee1905_association`、`coexisting_device_models`，以及未锚定结果的降级保护 `constrainUnanchoredSharedBehavior`。

### 5. 本地开发栈（`codex/local-zeek-replay`）

- `scripts/local/local-stack.sh` 全栈管理（`doctor` / `up` / `down` / `status` / `logs` / `sync` / `reset` / `purge`）。
- Zeek 增量镜像与 30 号只读回放；`deploy/compose/local.yml`。

### 6. 基线既有能力（menu-function-repair 其余提交）

路由器数量认定条件；4K 身份多地址拆分与北向授权刷新；N+T 身份接入；六类菜单与兼容路由重组；影子评估与证据回放；四视口验收工具。

## 三、迁移编号冲突（已在集成中修正）

两条开发线并行占用了同一批迁移编号。git 不会报冲突（文件名不同），但会破坏执行顺序与账本一致性。

| 引擎 | 冲突 | 处理 |
|---|---|---|
| PostgreSQL | `070`–`074` 各两份。其中 `ieee1905_client_associations` 两份**逐字节相同** | 删除重复那份；被动发现相关 4 份改到 `095`–`098`，排在既有 `083_discovery_latest` 之后 |
| ClickHouse | `032`/`033` 各两份（`identity_signal_stream` vs `passive_discovery_signal_stream`、`router_snmp_signal` vs `passive_discovery_response_stream`） | 被动发现两份改到 `034`/`035`，排在既有 `032`/`033` 之后；已确认无表/列依赖，且无代码引用旧文件名 |

修正后：PostgreSQL 98 份、ClickHouse 35 份，编号连续无重复，并在全新 PostgreSQL 上完整应用通过。

## 四、逐文件取舍依据（建议复核）

| 文件 | 取舍 | 依据 |
|---|---|---|
| `internal/discovery/repository.go` | 新增管线 `DevicesFiltered`/`loadDeviceViews` 取分支；`Devices` 恢复 HEAD 的投影表实现 | HEAD 的测试只应用 `058`+`083`，而分支查询联接 `029` 才有的 `device_address_leases`，二者契约不兼容 |
| `internal/store/ieee1905_associations.go`、`shared_behavior_materializer.go` | 取 HEAD | HEAD 为同一逻辑的更新版本（按客户端真实时间分桶、窗口边界、`NOT conflict`、更严格 endpoint/MAC 匹配） |
| `internal/store/shared_behavior_materializer_test.go` | HEAD 测试 + 补回分支独有的 `constrainUnanchoredSharedBehavior` 用例 | 两侧各有对方没有的测试；保护函数的调用点在非冲突区存活，必须保留其定义 |
| `internal/devicesignal/control.go` | 取 HEAD 解析器，补入分支独有的 `parseARP`/`parseNDP`/`parseWSDiscovery` | HEAD 不含这三种解析；初次逐块拼接会破坏流程，改为按 HEAD 结构插入 |
| `internal/devicesignal/packet_test.go` | 取 HEAD，补回分支独有的 2 个测试 | 另 3 个同名测试与 HEAD 的 `ieee1905_replay_test.go` 重复（git 因路径不同都保留，导致符号重定义） |
| `internal/sharedaccess/behavior.go` | 取 HEAD（`v12`、`coexisting_device_models`），保留分支的未锚定降级保护 | 分支侧是同一判定链路的旧基线 |
| 三个前端文件（`DiscoveryPage`、`SharedAccessPage`、`shared-access.spec.ts`） | 取 HEAD | 分支没有 `SourcesPage.tsx`（HEAD 菜单重构才引入），且分支版发现页缺「主动发现 / 采集任务」面板 |
| `scripts/deploy/deploy-backend.sh` | 取并集 | systemd 单元与 `assets/zeek` 两侧都需要；重启单元列表也取并集 |
| `internal/store/recognition_materializer.go` | 取分支 | 分支为更新的失败处理（2 分钟预算 + 专用失败状态写入） |

## 五、`codex/shared-risk-only` 未并入的依据

该分支不是增量，而是**与已并入实现相互竞争的方案**，且其能力已被更新实现覆盖：

| 维度 | 集成分支（HEAD / ieee1905 线） | `shared-risk-only` |
|---|---|---|
| 规则版本 | `shared-behavior/v12` | `shared-behavior/v10` |
| 确认锚点 | `coexisting_device_models`（型号共现 + 协议栈佐证） | `coexisting_device_identities`（仅稳定物理设备身份或 EasyMesh） |
| 当前/历史口径 | `current=true` + `expires_at` + 每作用域最新窗口 | `shared_behavior_generations` 代次模型 |
| 建案同步 | 合并已物化的 high/confirmed IP（较新重写） | `SharedBehaviorReader` + `closableKinds`（较早实现） |

支撑判断的证据：

1. **API/UI 增量已被覆盖**：该分支新增的字段（`risk_kind`、`disposition` 的 `confirmed_shared_access`/`confirmed_router`、`anchor_identities`、`device_lower_bound`、`router_brand`/`router_model`/`router_confidence`、`coverage_state`、`generation_id`、`known_device_basis`）在集成分支中**全部已存在**。
2. **独有文件依赖被替换的数据模型**：`shared_risk_audit.go`、`shared_risk_reset.go` 依赖 `shared_behavior_generations` / `shared_behavior_observation_history`，而 HEAD 无 `shared_behavior_generations` 表（自建表仅存在于该分支的 `072_shared_behavior_current_generations.sql`）。
3. **e2e 用例不可移植**：其断言的界面文案（`较可信路由器观察`、`独立证据源`、`较可信路由设备观察`、`共享行为已确认`）在集成分支的前端中 0 命中。
4. **强行合并会回退更新实现**：其 `operations.go` 变更替换了 HEAD 较新的建案同步逻辑。

因此可选处理：

1. 以现有集成分支语义为准，仅评估是否补充「代次模型 + 风险审计/重置」这套诊断能力（需同时移植其迁移，并确认与 HEAD 的 `current`/`expires_at` 口径如何共存）；
2. 以其风险通道设计为准，回退集成中采用的 HEAD 语义（需重做第四节的取舍）；
3. 不并入，由该分支作者 rebase 到集成分支后自行解决。

**这三项属于检测口径与数据模型的设计决策，需由该分支作者或现场负责人确认后执行。**

## 六、验证结论

| 项 | 结果 |
|---|---|
| `go build ./...`、`go vet ./...` | 通过 |
| 全新 PostgreSQL 应用全部 98 个迁移 | 通过；账本 `001`–`098` 连续无重复 |
| Go 单测（store / discovery / devicesignal / controlplane / policy / risk / notify / poison / behaviorreport / sharedaccess） | 与合并前基线**完全一致的失败集合**：`controlplane` 8 项、`store` 10 项，均为既有环境/测试隔离问题；`internal/discovery` 在修正投影表语义后由失败转为全绿 |
| 前端 `tsc -b`、生产构建、86 项单测、`scripts/check-api-contract.mjs` | 全部通过 |
| 合并过程中修正的缺陷 | 1 处真实语义回归（discovery 投影表）、2 组迁移编号冲突（PG 与 CH）、3 处重复测试函数、2 处硬编码迁移文件名 |

## 七、遗留事项

- 集成分支**未部署现场**，也未跑真实流量验收。
- `internal/discovery` 现有 `Devices`（投影表实现）与 `DevicesFiltered`（分支管线）两条语义相近但实现不同的路径，建议后续收敛为一条。
- 集成后 `internal/discovery` 的可见性口径需与前端发现页的窗口/分类筛选做一次一致性核对。
- 第五节的三选一决策未决。
