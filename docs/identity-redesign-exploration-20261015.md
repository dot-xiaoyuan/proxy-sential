# 身份链路重新设计（探索稿，2026-10-15）

> 背景：184 现场身份物化长期追不上流入（router-pilot 设备事件约 106 万条/小时，物化能力不到 5 条/秒），而且一出问题就互相放大。当前处于开发测试阶段，允许推倒重来。本文梳理身份数据到底在为谁服务，并给出面向防代理检测的设计。
> 依据：两轮代码调研（读方映射、检测需求），以及 `docs/site-184-storage-query-diagnosis-20261015.md`。

## 一、身份物化现在在为谁服务

结论：**身份物化主要服务设备中心和派生画像，风险评分本身基本不用它。**

| 服务对象 | 依赖强度 | 实际用到的数据 |
|---|---|---|
| 风险评分（证据、分数） | 弱或无 | 证据直接从 ClickHouse `normalized_events` 的 subject/payload 计算（`materialize.RunOnce` → `evidence.Analyze` → `risk.Batch`），不读 PG 历史表 |
| 共享窗口判定、处罚动作 | 强 | 账号在线会话：`policy_identity_observations`（`ListPolicySessions` 每次读 7 天全量 JSON 再在内存里对账），以及动作前实时读 Srun 在线清单 |
| 设备归属（共享/路由器证据落到终端） | 中 | DHCP 租约 `device_address_leases`（`ResolveDeviceAt` 时点查询） |
| 路由器配额、动作前置校验 | 中 | `account_sessions` |
| 设备中心列表与详情 | 强 | `endpoint_entities`、`identity_ip_mac_history`、`identity_access_history`、`account_sessions`，以及触发器驱动的 `endpoint_inventory_*` 十余张投影表 |
| 终端识别、账号标签、共享设备画像 | 强 | 上述表加触发器作业队列 |
| 几乎无读方 | — | `identity_binding_window_heads`、`identity_current_addresses`、`identity_session_refs`、`identity_account_refs`，以及没有读方的 ClickHouse `ip_event_features_10m` |

流量最大的部分（router-pilot 的 ARP，约 81 万条/小时）被逐条写进 `identity_ip_mac_history`，而这张表只服务设备中心展示和一处域名归因兜底。**写入成本最高的数据，业务价值最低。**

## 二、防代理检测真正需要的身份能力

| 需求 | 精度与窗口 | 当前实现的问题 |
|---|---|---|
| 时点归属：某园区、接入域下某 IP 在时刻 t 属于哪个账号、哪个登录代次 | 秒级；共享窗口 10 分钟，代理事务回扫 7 天 | 没有按 (scope, ip, t) 的索引；每分钟全量读 7 天 JSON 并反序列化全部快照 |
| 窗口内会话区间：上线、下线、心跳确认、覆盖区间都要落在同一账号和代次 | 秒级；心跳 5 秒，3 倍心跳内有效 | 同一份会话存了 4 套（`account_sessions`、`policy_identity_observations`、`identity_current_addresses`、`account_identity_session_projection`），语义各不相同 |
| 设备归属：某 IP 在时刻 t 对应哪个 MAC | 分钟级足够，DHCP 租约为准 | 租约表每条 DHCP 一行、没有保留期，当前有效的只有 2 条，却有 76 万行 |
| 动作前当前在线清单 | 实时 | 已经直接读 Srun，这部分合理 |

检测需要的是**两张小而精确的区间表**（账号会话、地址租约），保留"最长窗口 7 天 + 迟到余量"即可。现在却是为一年历史和设备中心投影设计的一整套重型链路。

## 三、根本问题：三种性质完全不同的数据被一条链路混在一起处理

| | A. 账号会话 | B. 地址绑定 | C. 终端状态 |
|---|---|---|---|
| 来源 | Srun 4K（权威） | DHCP（权威）、ARP/NDP（观测） | A 和 B 的派生，加识别指纹 |
| 量级 | 约 10 条/秒 | DHCP 约 7 条/秒；ARP 约 225 条/秒 | 约 8 万个终端，慢变化 |
| 精度 | 秒级、精确 | 租约秒级；ARP 分钟级即可 | 分钟级 |
| 用途 | 检测、处罚 | 检测（租约）、设备中心（历史） | 设备中心、识别、标签 |

现在 A、B、C 走同一个物化器，同一个事务，同一把全局锁，同一套逐行触发器。A 的精确性要求和 B 的流量叠加在一起，结果谁都没做好。

## 四、建议的设计

### 1. 账号会话台账（A）：直接写，不绕路

- 只用一张 PG 表 `auth_session_intervals`，字段：(scope, session_id, login_generation, account_id, ip, mac, started_at, ended_at, last_confirmed_at, source, change_seq)。
- 时点查询索引：`(scope, ip, started_at)`，配合 `ended_at` 过滤，或者用区间类型加 GiST 索引。
- **由收件箱 apply 直接写入**，不再导出到 ClickHouse 后读回。全量快照按差异应用：只关闭快照里已不存在的会话、补上新会话，不再整代重建。
- 取代 `policy_identity_observations`、`account_sessions`、`identity_current_addresses` 和引用表、`account_identity_session_projection`，也不再在查询时对账 `identity_full_snapshots`。
- 热保留 7 天加余量，过期的行归档到 ClickHouse。
- 检测查询只读与窗口 [t−10 分钟, t] 有重叠的会话，不再每分钟读 7 天。

### 2. 地址绑定（B）：大流量留在 ClickHouse 预聚合

- ClickHouse 新增 MV，把设备事件聚合进 `address_bindings_1m`（AggregatingMergeTree）：(sensor, campus, ip, mac, kind, bucket) → 最早时间、最晚时间、次数、样本事件 ID。ARP 不再逐条进 PG。
- DHCP 租约保留在 PG 小表 `address_leases`，用于检测热路径的时点归属。按区间存储，带保留期，同一 (ip, mac) 的续租合并成一行。
- 设备中心的"地址历史"改为按终端和时间范围分页读 ClickHouse 聚合表。AGENTS.md 允许详情历史独立、限定范围读取，ClickHouse 本来就承担事件和分析存储。
- 取代 `identity_ip_mac_history`、`identity_access_history`、`identity_signal_events_v1` 这份全量副本，以及 `identity_binding_window_heads`。

### 3. 终端状态（C）：每个终端一行当前状态，按变更集合更新

- PG 表 `endpoints`：每个终端一行，存主 MAC、当前 IP、当前账号、最后出现时间、识别结果，再配一个检索索引。设备中心列表只读这张表。
- 只有一个更新者，按水位每分钟取一次变更集合：从 `address_bindings_1m` 取新关闭时间桶里出现的 MAC，从会话台账取 `change_seq` 之后的会话，对这些终端做一次批量 upsert。最后出现时间按分钟合并刷新。
- 识别、账号标签、共享画像都排在终端状态之后，按同一个变更集合拉取。**不再使用逐行触发器。**
- 取代 `endpoint_inventory_*`（contributions、deltas、timers、associations、sessions、ip_points 等）以及相关触发器。

### 4. 检测读取路径

- 证据：照旧从 ClickHouse 事件和特征计算，这部分本来就不依赖 PG 身份表。
- 归属：会话台账做时点查询，租约表做设备归属。
- 动作：照旧在发送前实时读 Srun 在线清单，用会话台账核对登录代次。

### 5. 预期效果（估算，要在隔离环境压测确认）

- PG 写入从"每条事件逐行写入，再触发 3 到 5 行队列"变为三类批量写入：会话变化约 10 条/秒，租约变化约 7 条/秒，终端状态每分钟一批。
- ARP 只在 ClickHouse 里做一次聚合写入。
- 去掉全局身份写锁和逐行触发器之后，单块机械盘有望跟上。容量是否满足 10 倍目标，以压测结果为准。

## 五、需要你拍板的取舍

1. **设备中心新鲜度**：AGENTS.md 要求 5 秒可查询。按本设计，ARP 推出来的最后出现时间和地址变化会有 1 到 2 分钟延迟。会话和 DHCP 变化仍可以做到秒级。是否接受？
2. **ARP 历史精度**：从每条事件变为分钟桶（首次、末次、次数）。
3. **历史保留**：会话台账热查 7 天，地址绑定和会话归档放 ClickHouse，最多保留一年。这与 AGENTS.md 规定的"设备身份热查 30 天"有出入，需要调整约束，或者热查改为读 ClickHouse。

## 六、落地路径（开发阶段可推倒重来）

1. 新建会话台账、租约区间表、终端状态表和 ClickHouse 聚合 MV，与旧链路并存。
2. 收件箱直接写会话台账，同时从 ClickHouse 回放 7 天设备事件构建绑定和租约。
3. 影子比对：同一窗口下，新旧两套归属结果、共享窗口判定、设备中心列表要一致。
4. 把检测、处罚、设备中心切到新表。
5. 删除旧物化器、`identity_signal_events_v1`、历史表、`endpoint_inventory_*` 和相关触发器。
