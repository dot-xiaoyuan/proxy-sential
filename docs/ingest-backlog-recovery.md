# 采集积压与设备中心滞后：排查与修复记录（184 现场，2026-10-14）

本文记录 2026-10-14 对 `222.204.3.184` 设备中心数据滞后问题的排查结论、已上线的修复及其实测效果，以及恢复采集前必须确认的事项。结论均来自现场只读查询与逐项验证。

## 现象

- 设备中心 `endpoint_entities.last_seen` 与 `endpoint_recognition_summary.last_seen` 冻结在 `2026-10-14T07:10:19Z`，而 ClickHouse 中仍有事件写入。
- ingest 落后于采集约 20 GiB（`ttl.jsonl` 124 GB 中未读部分），车道持续报错。
- 采集阶段：为定位问题先停掉全部生产者（zeek 集群、device-signal、discovery、passive-discovery、identity 桥），只保留 ingest 排空既有数据。

## 已定位并修复（均已上线并验证）

| # | 根因 | 修复 | 实测效果 |
|---|---|---|---|
| 1 | ClickHouse 游标用行比较 `(a,b)>(x,y)`，主键索引提取不到 key range，退化为全表扫描 | 新增 `chAfterBound`，改写 6 条读路径（router recognition、passive discovery、domain evidence、proxy events、application events、application results） | 同批 2000 行 **41.6s → 1.9s**；granule 3263/3263 → **18/3263**；新旧写法返回逐字节一致 |
| 2 | 每批插入前的逐 `event_id` 幂等扫描是吞吐上限（索引表 64 行/granule、57 个 part，单 id 碰 31–57 granule） | 打开 `non_replicated_deduplication_window=100`（CH 迁移 037），新增 `PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY=clickhouse` 跳过扫描 | 每批写入 **3–11s → 0.5–1.1s**；排空 **25 → 67–75 MB/min**；按偏移逐批对账 `events_added == batches_read_sum`，重复 event_id = 0 |
| 3 | domain worker 把整批设备事件交给串行的身份写路径（同一 advisory lock），单次持锁上百秒 | 分块写入（150/批，与身份车道一致） | 锁等待 **72s → 采样多为 0**（最长 11s）；`queue full` 84 → 50 次/5 分钟 |
| 4 | 投影增量队列把整行 `to_jsonb` 存进 `endpoint_inventory_projection_deltas`，而唯一消费方只读 `{source,event_id,session_id}` | PostgreSQL 迁移 122 收窄 payload | delta payload 1499 B → **5 B**、472 B → **74 B**；最慢语句 40s → ≤18s |
| 5 | 容器内存与维护参数、统计信息 | CH 12 → 24 GiB、PG 8 → 16 GiB（含 runtime.env 持久化）；`maintenance_work_mem` 64 MB → 1 GB、`autovacuum_naptime` 30s、`cost_limit` 2000；重建热点表统计 | `identity_ip_mac_history` 估算 832 → **11,848,847**；`ANALYZE` 不再需要分钟级 |
| 6 | `ttl.jsonl` 无轮转配置（安装器不分发），涨到 124 GB | 补齐 `/etc/logrotate.d/proxy-sentinel-router-signals`、修正 shared-logrotate 单元并恢复定时器；安装器补分发 | 文件已轮转，ingest 按 file identity 排空归档 |

## 未解决的结构性问题

1. **设备事件产生速率与物化速率相差约 100 倍。** 现场实测 120 秒内：
   - ingest 读取 **236,430 条**（≈1,970 条/秒）；
   - 身份/设备物化路径只写 **861 插入 + 1,400 更新**（≈19 行/秒）；
   - 期间 `domain recognition queue full` 35 次（每次丢弃一个最多 6,500 条的批次）。

   即使把 domain worker 的分块与锁竞争都优化掉，串行身份写路径也远不足以吸收该速率；对账补偿按 10,000 条/批重放，同样追不上。PG 侧同时可见 33–35 个连接、8–16 个并发活跃语句、最长语句 378–485 秒。

2. **采集授权窗口已过期。** `config/router-capture-scope.json` 的 `valid_until=2026-10-09T05:26:00Z`（已过期 5 天），`access_domain` 仍是最初的 `bond0-router-minimal-overnight`。现场核查：`ttl.jsonl` 尾部 200 条事件全部带 `capture_scope_issue=capture_scope_outside_validity`，ClickHouse 中最近一小时 36,387 条 device 事件 **100%** 带该标记。需要按现场授权流程续期，或按原窗口停止采集。

3. 设备中心解冻依赖 ingest 排空指针走过 `07:10:19` 对应的文件位置；排空完成后才会自然推进，尚未恢复生产。

## 恢复采集前的检查清单

1. **授权窗口**：续期 `router-capture-scope.json`（新的 `valid_from`/`valid_until`/`access_domain`），或按原窗口停止采集。恢复采集前必须明确这一项。
2. **事件量**：`device-signal run --bucket 30s` 是主要音量来源。在物化路径达到约 2,000 行/秒之前，需要更粗的 bucket、更窄的 scope，或先完成物化路径重构；否则积压会立即重建。
3. **按序恢复**：identity 桥 → discovery/passive-discovery → device-signal → zeek 集群。每步之后核对 ingest 的 read/emit 计数、`collector_runs` 滞后与 `endpoint_entities.last_seen`。
4. **验收标准**：恢复 30 分钟后，`endpoint_entities.last_seen` 与 `now()` 的差应稳定在秒级；`domain recognition queue full` 应趋近 0；`endpoint_inventory_projection_jobs` 积压不再单调增长。

### 实验记录：多 worker 不能解决物化覆盖率（2026-10-14）

为提升覆盖率，为域名识别队列消费增加了并发度开关 `PROXY_SENTINEL_DOMAIN_WORKERS`（默认 1）。现场以 4 个 worker 实测 10 分钟：

| 指标 | 1 worker（基线） | 4 workers |
|---|---|---|
| `queue full` 丢弃 | 121 次/10 分钟 | 113 次/10 分钟（噪声范围内） |
| >5 秒 Lock 等待（60 秒采样） | 基本 0–2 | 0–7 |
| `domain recognition failed` | 约 2 次/10 分钟 | 43 次/10 分钟 |

结论：身份写入由事务级 advisory lock 串行，增加 worker 只增加争用而不提升吞吐。现场已回退为 1；并发开关保留在代码中（默认 1），但在这套硬件上不应开启。

真正的天花板是**串行身份写路径的单位事件成本**：实测单 worker 10 分钟完成约 34 个批次、丢弃 121 个（覆盖率约 22%），单 batch（约 6,500 事件）约 17 秒，即约 2.7 毫秒/事件；期间没有任何批次超过 20 秒，说明问题不是"个别批次卡死"，而是稳定的吞吐上限。要提升只能减少每事件的语句数/索引数，或降低事件产生量（见上文检查清单第 2 项）。

### 写放大：索引比堆大 3 倍，其中多个索引从未被扫描（2026-10-14）

`identity_ip_mac_history` 堆 2.7 GB、索引 8.5 GB。`pg_stat_user_indexes`（`stats_reset=never`，计数覆盖容器整个生命周期）显示两个 endpoint 覆盖索引从未被选中：

| 索引 | idx_scan | 大小 |
|---|---|---|
| `idx_ip_history_endpoint_observed` | 0 | 2,127 MB |
| `idx_ip_history_endpoint_has_ip` | 0 | 89 MB |
| `idx_ip_history_endpoint_list_cover` | 12,512 | 2,932 MB（在用） |

迁移 123 删除了与在用索引前导列相同的 `idx_ip_history_endpoint_observed`；现场先用
`DROP INDEX CONCURRENTLY` 手工删除以避免大表 ACCESS EXCLUSIVE 长锁等待（迁移文件本身用幂等
`DROP INDEX IF EXISTS` 记录账本）。表索引 8,517 MB → 6,390 MB，实测物化写入速率从约 12 行/秒
升到约 25 行/秒，车道无回归。

仍需按查询面语义判断的候选（尚未处理）：

- `identity_ip_mac_history.idx_ip_history_endpoint_has_ip`（0 扫描，89 MB，partial endpoint_id）；
- `policy_identity_observations` 上 `policy_identity_time` / `policy_identity_account_time` /
  `policy_identity_scope_time`（均 0 扫描，合计 157 MB）；
- `endpoint_entities.idx_endpoint_page_order`（0 扫描，99 MB）与 `idx_endpoint_entities_mac`（0 扫描，4.6 MB）。

这些索引可能服务于本轮排查期间未被访问的页面（例如设备中心列表），删除前需确认对应查询路径不再依赖它们。

### 写放大之二：行级触发器与任务队列索引（2026-10-14，第 11–12 轮）

**受控基准**（探针表与真表结构/索引相同、全部回滚）证明 `identity_ip_mac_history` 的三个行级触发器是身份写入路径的主要成本：

| 场景（同样 300 行） | 改前 | 删除任务队列未使用索引后 |
|---|---|---|
| 探针表（无触发器） | 12.8 ms | 14.0 ms |
| 真表（3 个触发器） | **59,081 ms** | **1,178 ms** |
| 批量任务入队 upsert | 41,126 ms | 1,968 ms |

逐项隔离显示 `record_inventory_projection_delta` 只占约 45 ms，开销集中在两个"任务入队"触发器对
`endpoint_inventory_projection_jobs` 的 upsert；而该表堆 20 MB、索引 112 MB，其中
`inventory_projection_pending`（53 MB）等 7 个索引扫描 0–1 次（表小到顺序扫描更便宜）。
迁移 124 删除这些索引后（现场用 `DROP INDEX CONCURRENTLY`），触发器路径快了约 50 倍。

**仍然存在**：现场仍可见 `domain batch timing: events=6456 devices=1863 identity=1m38.393s` 的批次，
即身份写入阶段仍约 **53 ms/设备事件**，而其中 history 插入现在只占约 4 ms，其余来自每事件十余条
语句（`endpoint_entities`、`policy_identity_observations`、`identity_current_addresses`、租约、画像、
`legacyAuthorityEvents` 查询等）及其各自触发器。要把物化覆盖率从约 20% 提升到 100%，需要把
"每事件多条语句"改为按批聚合写入，或按前述检查清单降低事件产生量。
