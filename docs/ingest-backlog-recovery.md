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
| 7 | 身份快照投影与身份写入用两把互不排斥的 advisory lock，行级触发器使二者以相反顺序锁同一批任务行，形成死锁自锁死 | `projectIdentitySnapshot` 并入身份写入锁，busy 时不写入也不删队列行（详见下节） | 死锁 **42–45 次/小时 → 0**；`endpoint_entities` 恢复提交，5 分钟 1394 次更新 |

| 8 | `normalized_events` 上挂着 12 个物化视图，其中 `passive_discovery_events_v1_mv` 的目标表自 035 起已被 v2 取代，属纯死写 | ClickHouse 迁移 038 删除该死物化视图（保留目标表与历史数据） | 扇出 12 → 11；part 速率 **184–202 → 174 次/分钟**；目标表 180 秒内 0 个新 part |

### 身份物化的死锁自锁死（2026-10-14，第 14 轮；已修复并上线）

这是"设备中心数据积压"的直接原因，独立于磁盘与速率问题。

**现象**：`identity_applied_events` 停在 `09:42`；`identity_materializer_cursors.live` 长时间
不再推进；`identity-materializer` 每小时打印 42–45 次
`identity snapshot materializer: ERROR: deadlock detected (SQLSTATE 40P01)`。每条都是整事务回滚，
下一轮重新读到同一批数据再次成环——**反复重试却永不提交**，因此不产生任何"卡住"的错误页面，
只表现为设备状态停止推进。

**PostgreSQL 死锁图（12:39:06 UTC）** 的环两端固定为：

```
Process 52768: INSERT INTO endpoint_entities(...)            -- writeIdentityEventsTx 路径
Process 50140: INSERT INTO account_identity_session_projection(...)  -- projectIdentitySnapshot
Process 52768 waits for ShareLock on transaction ...; blocked by process 50140.
Process 50140 waits for ShareLock on transaction ...; blocked by process 52768.
CONTEXT: while inserting index tuple (2022,1) in relation "endpoint_inventory_projection_jobs"
  ← enqueue_inventory_projection() → enqueue_inventory_projection_id()
```

**机制**：`endpoint_entities`、`account_identity_session_projection` 等 7 张表都带
`inventory_projection_change AFTER ... FOR EACH ROW` 触发器（迁移 103），每行写入都会
upsert `endpoint_inventory_projection_jobs`。身份写入路径按 `endpoint_id` 排序入队，
而快照投影按快照事件顺序入队；两者并发时对同一批任务行以相反顺序加锁，必然成环。

**根因**是两把不同的 advisory lock，彼此不排斥：

- 身份写入路径 `writeIdentityEventsTx`：`hashtextextended('proxy-sentinel-identity-write',7137)`；
- 快照投影 `projectIdentitySnapshot`：只用 `hashtextextended(scope,7136)`。

**修复**（`internal/store/account_projection.go`）：投影在持有 scope 锁后并入身份写入锁，
用 `tryIdentityWriteLock` 非阻塞尝试；失败返回新增的 `errIdentityWriteBusy`，
`projectPendingIdentitySnapshots` 收到后回滚且**不删除队列行**（快照留待下一轮重试，
不静默丢任务）。回归测试 `TestAccountSnapshotProjectionDefersToIdentityWriter`
验证"持锁期间不启动、不写入、不丢队列，释放后正常投影并清空队列"。

**验收（发布 `2026.10.14-identity-projection-lock1`，previous=`2026.10.14-domain-failfast1`，
`/readyz=200`，9 个应用服务全部切到新二进制）**：

- 切换后 12 分钟：PG 日志与各单元**死锁 0 次**（此前每 20 分钟 7 次），
  `identity-materializer` ERROR 0 条；
- 恢复 drain 满负荷后 5 分钟：83 个批次、**82 提交、0 失败**；
  `endpoint_entities` 近 5 分钟提交 1394 次更新，设备状态重新开始推进。

排查中同时排除的项：`recognition_materializer`（每个 lease 只处理一个 endpoint，单行事务
不可能成环）、`device_names_postgres`（`device_name_notes` 只在单 endpoint 的改名事务里写）。
`identity_applied_events` 停在 `09:42` 经核实**不是缺陷**：inbox
`identity_pipeline_scopes` 的 `pending=0`（accepted=56911 已全部 applied），
生产端停采后本就无新输入。

## 未解决的结构性问题

1. **设备事件产生速率与物化速率相差约 100 倍。** 现场实测 120 秒内：
   - ingest 读取 **236,430 条**（≈1,970 条/秒）；
   - 身份/设备物化路径只写 **861 插入 + 1,400 更新**（≈19 行/秒）；
   - 期间 `domain recognition queue full` 35 次（每次丢弃一个最多 6,500 条的批次）。

   即使把 domain worker 的分块与锁竞争都优化掉，串行身份写路径也远不足以吸收该速率；对账补偿按 10,000 条/批重放，同样追不上。PG 侧同时可见 33–35 个连接、8–16 个并发活跃语句、最长语句 378–485 秒。

2. **采集授权窗口已过期。** `config/router-capture-scope.json` 的 `valid_until=2026-10-09T05:26:00Z`（已过期 5 天），`access_domain` 仍是最初的 `bond0-router-minimal-overnight`。现场核查：`ttl.jsonl` 尾部 200 条事件全部带 `capture_scope_issue=capture_scope_outside_validity`，ClickHouse 中最近一小时 36,387 条 device 事件 **100%** 带该标记。需要按现场授权流程续期，或按原窗口停止采集。

3. 设备中心的推进现在受两条互相独立的链路限制，都不再是死锁：
   - **投影积压**：`endpoint_inventory_projection_jobs` 仍有约 5.0 万条
     `processed_generation<dirty_generation`；投影车道的消费速度与身份写入新产生的脏标记
     大致相当，积压不降。同一张任务表上每 20 分钟约 830 次 `FOR UPDATE NOWAIT`
     失败（`could not obtain lock on row in relation "endpoint_inventory_projection_jobs"`），
     说明争用仍集中在"每行触发器 upsert 同一张任务表"这一形状上。
   - **ClickHouse 合并放大**：`system.part_log` 实测每分钟新增约 200 个 part、
     合并重写约 190 MiB；`pidstat -d` 显示 clickhouse-server 单进程写 31 MB/s（峰值），
     而 `iostat` 显示磁盘 **util 100%、aqu-sz 7–14、r_await 71–107 ms**，
     整机可持续读写合计仅约 9 MB/s。同批事件被写入约 5 张表
     （`normalized_events` 177.6M/24.8GiB、`identity_signal_events_v1` 177.3M/13.7GiB、
     `normalized_event_ids_v1`+`v2` 各 177.6M/13.5GiB、`normalized_event_features` 177.6M/7.1GiB，
     另有 `passive_discovery_events_v1`/`v2` 各 104.5M/6.5GiB 双写），
     叠加 4 MiB 批（每 part 仅约 5,900 行）造成的 part 碎片化。
     PostgreSQL 只需约 0.5 MB/s 写入却因此被饿死，身份语句单条耗时 0.5–4.4 秒。
     方向：**不能靠单纯加快 drain 解决**（见下节负结果），需要减少扇出目标表、
     降低事件量或重构分析路径。

### 实验记录（负结果）：放大 ingest 批次不能解决设备滞后（2026-10-14，第 15 轮）

思路：ClickHouse 的 part 数 = 插入次数 × 扇出目标数（实测 11–13），因此把 ingest 的
`--max-batch-bytes` 从 4 MiB 放大到 32 MiB（同时把该单元的 `MemoryMax` 由 2G 抬到 4G），
期望 part 与合并量按比例下降。现场实测约 4 分钟：

| 指标 | 4 MiB（基线） | 32 MiB | 结论 |
|---|---|---|---|
| drain 吞吐 | 42–66 MiB/min | **152 MiB/min** | 排空确实快了 2.3–3.6 倍 |
| `normalized_events` 新 part | 16–18 次/分钟 | **近 0** | part 碎片化被消掉 |
| 总 part 速率 | 174–191 次/分钟 | 约 2 次/分钟 | 同上 |
| `endpoint_entities` 5 分钟更新 | 2,280 | **991** | 设备物化反而减半 |
| domain 识别 | 偶发 `queue full` | 持续 `timeout: context deadline exceeded` | 分析路径被打垮 |
| ingest 内存 | 1.95 GB | **4.29 GB（顶到 cgroup 上限）** | 触及容量上限 |

**已回退**到 4 MiB（保留 `MemoryMax=4G` 作为余量），回退后实测：part 191 次/分钟、
内存 1.40 GB、死锁 0、`endpoint_entities` 5 分钟更新回升到 1,589、
identity-materializer 零错误。

结论：**瓶颈不在 drain，而在 domain/身份分析路径的消费能力。** 提高 ingest 速率只会把
压力推到下游，让设备状态更差；`domain recognition queue full` 的持续出现说明 4 MiB
时分析路径本身也已到容量上限。这也解释了为何"事件量决定"是本问题的前置条件：
在分析路径吞吐提升之前，任何提高采集或排空速率的手段都不会改善设备中心。

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

### 队列消费与对账的锁竞争（2026-10-14，第 12 轮）

删除任务队列未使用索引后，触发器路径快了约 50 倍（真表 300 行插入 59,081 ms → 1,178 ms），
但**设备事件物化的覆盖率并没有改善**（仍约 2–3%）。进一步测量表明两个消费者在争抢同一把
身份写锁：

- 实时队列 worker：单批约 6,500 事件 / 1,863 设备，身份阶段实测 1 分 38 秒（约 19 设备事件/秒）；
- 对账窗口（每 5 分钟一次、预算 4 分钟、每次 10,000 事件）同时重放约两天前的积压，
  长时间持有同一把锁。

失败批次原先最多重试 3 次 × 2 分钟预算，会把 worker 钉死在同一个批次上（现场 10 分钟 42 次失败、
只完成 1 个批次、丢弃 168 个）。已改为**单次尝试即放弃**（失败批次交给对账），失败次数降到 23 次/5 分钟，
但覆盖率仍约 3%，说明瓶颈是身份写路径的单位事件成本（每事件十余条语句），而不是重试策略。

要达成 100% 覆盖，只有两条路：**降低事件产生量**（`device-signal --bucket` 由 30s 调粗到 5m，
可把约 1,700 事件/秒降到约 170，与当前物化容量相当），或**重构身份写路径**为按批聚合写入。

## 恢复采集的可执行步骤（需先取得授权）

### 前置决定（未决定前不要执行第 2 步以后）

1. **授权窗口**：`config/router-capture-scope.json`（0600，经 `PROXY_SENTINEL_CAPTURE_SCOPE_CONFIG` 引用）
   的 `valid_until=2026-10-09T05:26:00Z` 已过期；要么按现场流程续期（新的
   `valid_from`/`valid_until`/`access_domain`），要么按原窗口结束采集。
2. **事件量**：`proxy-sentinel-device-signal.service` 的 `ExecStart` 内含 `--bucket 30s`（无 drop-in）。
   物化容量实测约 370 事件/秒，当前产生约 1,700 事件/秒；建议改为 `--bucket 5m`（约 170 事件/秒）。

### 步骤与核对点

| # | 操作 | 期望结果 |
|---|---|---|
| 0 | `docker exec proxy-sentinel-postgres psql -U proxy_sentinel -d proxy_sentinel -Atc "select (124325110008-committed_offset)/1048576 from ingest_checkpoints where source_kind='device-signals'"`；`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/readyz` | 剩余 ≈ 0 MiB；readyz 200 |
| 1 | 按决定更新 `config/router-capture-scope.json`（若续期） | 新窗口覆盖当前时间；文件仍 0600 |
| 2 | 编辑 `proxy-sentinel-device-signal.service` 的 `--bucket 30s` → `--bucket 5m`，`systemctl daemon-reload` | `systemctl cat` 显示新参数 |
| 3a | `systemctl start proxy-sentinel-ncu-identity-sync` | active；`journalctl -u ... -n 5` 无 `operation_error` 激增 |
| 3b | `systemctl start proxy-sentinel-discovery proxy-sentinel-passive-discovery` | active；`discovery_sources` 不报错 |
| 3c | `systemctl start proxy-sentinel-device-signal` | active；`stat -c %s data/device-signals/ttl.jsonl` 持续增长 |
| 3d | `systemctl start proxy-sentinel-zeek-cluster`（内部执行 `zeekctl deploy`） | `zeekctl status` 全部 running；接口日志出现在 `data/zeek/logs/current/` |
| 4 | 恢复 30 分钟后验收 | 见下 |

### 验收标准（恢复后 30 分钟）

- ingest：`ingest_diagnostics` 的 `read`/`emitted` 持续增长，`collector_runs` 滞后不再扩大；
- 域名识别：`journalctl -u proxy-sentinel-ingest | grep -c "queue full"` 趋近 0（bucket=5m 时应能跟上）；
- 设备中心：`endpoint_entities.last_seen` 与 `now()` 的差稳定在分钟级并持续缩小；
- 投影：`endpoint_inventory_projection_jobs` 积压不再单调增长，`endpoint_inventory_projection_state.last_error` 为空。

### 回滚

任一验收项不达标：先 `systemctl stop` 对应的生产者（尤其 device-signal 与 zeek 集群）让系统回到排空状态，
保留 `previous` 发布指针用于应用回退；数据库迁移只向前兼容，不假定回退会撤销迁移。

### 设备中心新鲜度的诚实口径（2026-10-14 实测）

`endpoint_entities.last_seen` 的最大值（现场 07:10）会掩盖真实陈旧度，必须看分布：

| 指标（75,030 台设备） | 值 |
|---|---|
| 近 1 小时内有更新 | **0** |
| 近 6 小时内有更新 | 532 |
| 近 24 小时内有更新 | 11,143（15%） |
| 中位数 `last_seen` | **10-12 11:20（约 2 天前）** |

结论：设备中心的问题不是"前沿滞后"而是**物化覆盖不足** —— 即使 ClickHouse 排空完成，
只要物化路径仍只覆盖约 3% 的事件流，多数设备的当前状态就会继续停留在两天前。
因此"设备中心数据积压"的根治必须落在第 2 项决定（降量或重构物化路径）上，
而不是继续优化 ingest 排空。
