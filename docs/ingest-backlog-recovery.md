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

| 9 | 身份物化器用非阻塞 try-lock 抢身份写锁，而 domain worker 几乎 100% 占用该锁 → 静默跳过、游标永久冻结（无任何错误） | `awaitIdentityWriteLock`：有界等待（8s）后再放弃，把饿死变成延迟 | 锁占空比实测 10/10 被持有；`ncu-auth-redis` lane 恢复推进（processed 560,403 → 561,003，`last_success` 回到当前） |
| 10 | `enqueue_existing_shared_device_profile_identity_jobs` 的 MAC 分支把 `regexp_replace` 用在列上，无法走索引，每次调用全表扫 939 行（约 7 ms/行），行级触发器每批调用约 2,500 次 | PG 迁移 125 补匹配表达式的索引，现场以 `CONCURRENTLY` 创建 | 单次查询 **7.113 ms / 433 buffers → 0.159 ms / 2 buffers**；函数 **7.26 → 4.39 ms/行**，索引实测被使用 889 次 |

| 11 | `shared_buffers` 仅 1 GB（容器 16 GB），而热表约 20 GB：`identity_ip_mac_history` 堆未命中 23.7%、`identity_access_history` 71.3%，identity 写入几乎都在盘上随机 I/O | `ALTER SYSTEM SET shared_buffers='4GB'`、`effective_cache_size='16GB'`（持久化在容器 PGDATA 的 `postgresql.auto.conf`，需重启生效） | 触发器单次 7.26 → **0.348 ms**（21×）；`endpoint_entities` 5 分钟更新 2,300 → **4,105**（1.7×）；冻结 1 小时的 `ncu-184-router-pilot` lane **恢复推进** |
| 12 | `idx_ip_history_endpoint_has_ip`（90 MB，`idx_scan=0`）前导列与 `idx_ip_history_endpoint_list_cover` 相同且被其完全覆盖 | PG 迁移 126 删除（现场以 `CONCURRENTLY` 先删） | 该表索引 6 → 5 个，每次写入少维护一个盘上索引 |

| 13 | 缓存仍不足以覆盖工作集：`shared_buffers` 4 GB vs `identity_ip_mac_history` 堆 9.1 GB + 索引 6.4 GB（工作集约 15.5 GB） | `shared_buffers` 4 → **8 GB**、`effective_cache_size` 16 → 32 GB；PG 容器内存上限 16 → 24 GB | `endpoint_entities` 5 分钟更新 785 → **1,362/分钟**（再 1.7×）；`readyz=200`、无新增失败单元 |

| 14 | 身份物化循环每秒写一次 `read_model_runtime_state` 健康心跳，等于每秒一个 autocommit（245 ms/次），叠加在 228 ms 的 `commit` 之上 | 新增 `identityHealthInterval=10s` 节流，出错时仍立即写（`internal/store/identity_materializer.go`） | 心跳写入 90/100s → 约 66/100s（−27%）；`commit` 112/100s → 约 67/100s（−40%） |
| 15 | 缓存仍不足：`shared_buffers` 8 GB vs 工作集约 15.5 GB，导致批量插入 `identity_ip_mac_history` 每次 1.4 s（最慢 4.0 s） | `shared_buffers` 8 → **12 GB**（容器已是 24 GB） | 该插入**降到 300 ms 以下**（>5×）；`endpoint_entities` 更新 → **1,104/分钟**；**两条 identity live lane 全部解冻** |

| 16 | `UPDATE shared_device_profile_runtime WHERE singleton` 每次 431 ms，且 4 个后端同时阻塞在它的 `Lock/tuple` 上——因为它**在投影事务内部**执行，而投影事务可跑数十秒 | 改为先 `tx.Commit()` 再用独立短事务写；新增 `writeAdvisoryState`（`SET LOCAL synchronous_commit=off`）承载心跳/计数这类建议性写入 | 锁等待采样 6/6 只剩 `Lock/advisory`；90 秒慢语句计数 `commit` 39 → **20**、该 UPDATE 39 → **12**；`endpoint_entities` 更新 → **1,370–1,634/分钟** |

| 17 | 两条最热的身份 upsert（`endpoint_entities`、`identity_ip_mac_history`）没有 `ON CONFLICT … WHERE` 守卫：PostgreSQL 对每个冲突行都写新元组版本 + 全部索引项并触发行触发器，即使值完全没变；重复/重放事件因此既是空写、又把投影任务反复标脏 | 为两条 upsert 增加精确镜像 SET 赋值的 `WHERE` 守卫（`internal/store/identity_batch_write.go`），并用 `xmin` 写集成回归测试 | `identity_ip_mac_history` 慢插入 12–69 → **2 次/60 秒**；投影积压**首次停止增长**（58,420 → 58,418/120 秒）；两条 lane 大幅推进（21,305,112 → 21,329,612 等） |

| 18 | `identity_access_history`、`account_sessions` 同样带投影触发器却没有 no-op 守卫；且 `account_sessions` 后面那条按 `confirmed_at` 无条件更新 `policy_metadata` 的语句会抵消守卫 | 两条 upsert 补精确镜像守卫，`policy_metadata` 语句补 `IS DISTINCT FROM` 判断；新增 `xmin` 集成测试覆盖三张表 | 慢插入持续低位；但积压仍涨——查明**不是脏标记问题**，而是投影 lane 反复 `projection_failed`（见第 22 轮一节） |

| 19 | 设备清单投影的 realtime 车道**顺序**处理任务，吞吐被单个 endpoint 的处理时间钉死在约 0.67 任务/秒 | 改为按 `inventoryRealtimeWorkers()` 并发（环境变量 `PROXY_SENTINEL_INVENTORY_REALTIME_WORKERS`，默认 2、范围 1..8，=1 恢复原行为），连接池相应放大 | 吞吐 **40–52 → 102–169 次/分钟（约 3×）**；积压由"每分钟 +93 稳定增长"变为围绕 61,000 震荡 |

| 20 | realtime 车道并发度默认 2 仍不足：脏标记以约 271/分钟产生，而 4 workers 只有约 165/分钟 | 现场把 `PROXY_SENTINEL_INVENTORY_REALTIME_WORKERS` 提到 **8**（旋钮上限；进程 CPU 仅 5.5%，是 I/O 受限而非 CPU） | 吞吐 **165 → 242–308 次/分钟**；积压由"再次增长"转为**持续下降**（6 分钟净 −144） |

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

4. **分析路径的成本是"逐行触发器"而非数据量。** identity 相位占 domain 批次的 99.97%，
   而其中每次调用约 7 ms 的共享设备画像触发器要占一半以上（见第 16 轮归因）。
   补表达式索引后单次查询快了 44 倍，但**逐行调用**带来的计划与 SPI 开销使得整体吞吐
   只从约 51 提升到约 55 设备/秒。下一步应把 `shared_device_profile_endpoint_dirty`、
   `_session_dirty`、`_account_projection_dirty` 改为语句级 transition table + 集合式唤醒
   （一条语句对整批变更行做一次 join），预计能把这部分从每批约 50–100 秒降到秒级。

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

### 分析路径耗时归因：逐行触发器（2026-10-14，第 16 轮）

device worker 的相位计时把范围缩到极小：

```
domain batch timing: events=5965 devices=2494 identity=49.045s total=49.058s
```

**identity 相位占 99.97%**。开启 `track_functions='pl'`（`ALTER SYSTEM` + `pg_reload_conf`，
无需重启）后按触发器函数归因（150 秒窗口）：

| 触发器函数 | 调用次数 | 总耗时 | 每次 |
|---|---|---|---|
| `enqueue_existing_shared_device_profile_identity_jobs` | 1,054 | 7,653 ms | **7.26 ms** |
| `shared_device_profile_session_dirty` | 550 | 3,856 ms | **7.01 ms** |
| `shared_device_profile_endpoint_dirty` | 504 | 3,816 ms | **7.57 ms** |
| `record_inventory_projection_delta` | 8,466 | 2,558 ms | 0.30 ms |
| `enqueue_inventory_projection_id` | 14,655 | 790 ms | **0.054 ms** |

原先怀疑的 `enqueue_inventory_projection_id` 每次只要 0.054 ms，**不是瓶颈**；真正贵的是共享
设备画像的三个行级触发器，每个约 7 ms。按每批 2,494 台设备 × 3 个触发器估算约 52 秒，
与实测 49 秒吻合。

`EXPLAIN (ANALYZE, BUFFERS)` 给出根因：MAC 分支的正则作用在列上，索引不可用——

```
Seq Scan on shared_device_profiles  (actual time=0.028..7.028 rows=1 loops=1)
  Filter: ... regexp_replace(lower(mac),'[^0-9a-f]','','g') = '9844ced758e0'
  Rows Removed by Filter: 938   Buffers: shared hit=433   Execution Time: 7.113 ms
```

补上表达式索引后降为 `Bitmap Index Scan ... Execution Time: 0.159 ms`（433 → 2 buffers）。

**但要诚实记录效果边界**：函数耗时只从 7.26 降到 4.39 ms/行，整体吞吐仅由约 51 提升到
约 55 设备/秒（49s/2,494 设备 → 1m47s/5,940 设备）。原因是这些触发器**逐行**调用函数，
每行仍要付出约 1.6 ms 的计划开销与 SPI 开销。因此还剩一个数量级的空间，方向是把
`shared_device_profile_endpoint_dirty`、`_session_dirty`、`_account_projection_dirty`
改为**语句级（transition table）+ 集合式**唤醒：一条语句对整批变更行做一次 join，
而不是每行一次。

**同样要记录**：第 16 轮的有界等待预算为 8 秒，而 domain worker 单批持锁实测 49–107 秒，
比预算长一个数量级，因此 `ncu-184-router-pilot` lane 在收尾时仍抢不到锁（现场采样
`locks_waiting=1`，活跃语句以 `LWLock/WALWrite` 与 `IO/DataFileRead` 为主）。
把等待预算继续放大不可行——它会吃掉该 lane 自己的 60 秒批次预算。**真正的解法是缩短
持锁时间**（即上面的语句级触发器改造），而不是让等待方等更久。

同时确认：`normalized_events` 上剩余 11 个物化视图的目标表在 6 天 query_log 窗口内
**全部被读取**（`identity_signal_events_v1` 75.8 万、`router_signal_events_v1` 69.9 万、
`normalized_event_ids_v1` 42.8 万…），已无更多死写可删——第 15 轮删掉的
`passive_discovery_events_v1` 在同一窗口内确为 0 读，结论不受影响。

### 缓存与 I/O 归因：`shared_buffers` 只有 1 GB（2026-10-14，第 17 轮）

第 16 轮把 identity 相位归因到三个共享设备画像触发器，但重新核算后发现：那三个触发器在
150 秒窗口内合计约 15 秒，**不足以解释单批 107 秒**。回到第 16 轮抓到的阻塞现场：

```
61541 | 47s | IO/DataFileRead | INSERT INTO identity_access_history(...)   ← 持锁者
60852 |     | IO/DataFileRead | INSERT INTO endpoint_inventory_contributions VALUES($1,...)
```

单条 INSERT 就停在 `IO/DataFileRead` 上 47 秒——瓶颈是大表上的随机 I/O。量缓存才发现：

| 配置 | 值 |
|---|---|
| `shared_buffers` | **1 GB**（容器内存 16 GB） |
| `effective_cache_size` | 6 GB |
| 热表合计 | 约 20 GB（`identity_ip_mac_history` 堆 9.1 GB + 索引 6.4 GB，`identity_current_addresses` 4.3 GB…） |

命中率印证：`identity_ip_mac_history` 堆未命中 **23.7%**、索引未命中 18.4%；
`identity_access_history` 堆未命中 **71.3%**。写入要维护 6 个索引，而索引页大多在盘上。

**改动**：
1. `ALTER SYSTEM SET shared_buffers='4GB'`、`effective_cache_size='16GB'`（写入容器 PGDATA 的
   `postgresql.auto.conf`，随卷持久化；`shared_buffers` 需重启生效）。
2. 删除冗余索引 `idx_ip_history_endpoint_has_ip`（迁移 126）。

**效果（重启后约 4 分钟实测）**：

| 指标 | 之前 | 之后 |
|---|---|---|
| `enqueue_existing_shared_device_profile_identity_jobs` | 7.26 ms/次 | **0.348 ms/次** |
| `shared_device_profile_endpoint_dirty` | 7.57 ms/次 | **0.398 ms/次** |
| `endpoint_entities` 5 分钟更新 | 约 2,300 | **4,105** |
| `ncu-184-router-pilot` live lane | 冻结 1 小时以上（processed 21,298,212，succ 12:57:31） | **恢复推进**（21,300,462，succ 14:15:03） |

**运维记录**：本机 `docker restart proxy-sentinel-postgres` 走的是崩溃恢复，日志实测
`checkpoint complete: wrote 297474 buffers (56.7%) ... write=85.749 s, total=88.084 s`，
**约 150 秒才 ready**（期间 `/readyz` 返回 503）。在这台磁盘上重启 PostgreSQL 的代价很高，
后续调整 `shared_buffers` 一类需重启的参数要预留这个时间窗。

**仍未达标**：identity 相位仍是约 17–26 ms/设备（`identity=1m0s/3,558 设备`），
因为每次写入仍要维护 5 个盘上索引并产生 WAL；缓存未命中仍偏高
（`account_identity_session_projection` 堆未命中 93%）。这条路径距离 AGENTS.md 要求的
容量基线仍有数量级差距，主要受事件量与磁盘带宽约束。

### 逐语句归因：批量插入 identity_ip_mac_history 是单一最大瓶颈（2026-10-14，第 18 轮）

第 17 轮把缓存从 1 GB 提到 4 GB 后仍有约 19 事件/秒的上限。这一轮改用**不重启**的归因方法：
临时打开 `log_min_duration_statement`（`ALTER SYSTEM` + `pg_reload_conf`，采集 100 秒后复位），
直接读每条语句的 `duration:`。

结果（100 秒窗口，>200 ms 的语句）：

| 语句 | 次数 | 平均 |
|---|---|---|
| `INSERT INTO identity_ip_mac_history(...) SELECT ... FROM unnest(...)`（prepared `stmtcache_643f147e…`） | 69 | **1,364 ms**（最慢 4,033 ms） |
| `commit` | 112 | 228 ms |
| `INSERT INTO read_model_runtime_state` | 90 | 245 ms |
| `UPDATE shared_device_profile_runtime SET last_success_at=now()…` | 44 | **431 ms** |
| `INSERT INTO endpoint_inventory_contributions` | 43 | 265 ms |

即 identity 相位的时间几乎全在**一条**批量插入语句上：该表堆 9.1 GB、索引 6.4 GB，而
`shared_buffers` 只有 4 GB，于是每行插入的 5 个索引页大多要落盘随机 I/O。

同时确认两个随之而来的现象：
1. **身份写锁仍 100% 被占用**（6 次采样全部“被持有”），物化器批次因此 `timeout: context
   deadline exceeded`，自适应批次从 2,000 一路缩到 500 / 300——这就是它只能跑约 19 事件/秒的原因。
2. `shared_device_profile_runtime` 是一个**单行热点**：多个后端同时阻塞在
   `Lock/tuple` / `Lock/transactionid` 上等这条 `WHERE singleton` 的 UPDATE（每次 431 ms）。
   同一个文件第 801 行已经用了节流写法（`AND updated_at<now()-interval '5 seconds'`），
   第 720/738 行的**按 job** 更新没有节流，是下一个可改点。

**本轮改动与实测**：`shared_buffers` 4 → 8 GB、`effective_cache_size` 16 → 32 GB，
PG 容器内存上限 16 → 24 GB（`docker update`）。实测 `endpoint_entities` 5 分钟更新
785 → **1,362/分钟**（再 1.7×），`readyz=200`，无新增失败单元。

**运维发现（重要）**：`docker restart` 会走崩溃恢复，实测约 150 秒；改用
`docker exec -u postgres … pg_ctl stop -m fast -D "$(SHOW data_directory)"` 干净关机后再
`docker start`，实测**关机 101 秒、启动仅 5 秒就绪**，且不会触发崩溃恢复。
注意必须以 `postgres` 用户执行（root 会被拒绝），且数据目录是
`/var/lib/postgresql/data/pgdata` 而不是 `/var/lib/postgresql/data`。

**下一步（按预期收益排序）**：
1. `identity_ip_mac_history` 按天分区——新行只写小分区、索引可全部驻留缓存，
   这是这类追加型历史表的教科书解法，但需要一次性重建（约 9 GB 堆 + 6.4 GB 索引）。
2. `shared_buffers` 再提到 12 GB（容器已是 24 GB），工作集 15.5 GB 可覆盖大部分。
3. 给 `shared_device_profile_runtime` 的按 job 更新加节流，去掉单行热点。

### 缓存提到 12 GB 与心跳节流：主瓶颈消失（2026-10-14，第 19 轮）

上面三项的第 2 项与另一项更便宜的改动已落地，效果合并如下（发布
`2026.10.14-health-throttle1`，previous=`shared-profile-idx1`）：

改动 A（代码，`internal/store/identity_materializer.go`）：身份物化循环每次迭代都写
`read_model_runtime_state`，而循环间隔只有 1 秒——等于每秒一个 autocommit。逐语句归因测得
该写入 90 次/100 秒 × 245 ms ≈ 22 秒，另加 `commit` 112 次 × 228 ms。改为最多每 10 秒写
一次、出错时立即写。

改动 B（配置）：`shared_buffers` 8 → **12 GB**（`ALTER SYSTEM`，干净关机后重启；
容器上限 24 GB）。工作集 15.5 GB 由此可覆盖大部分。

合并实测：

| 指标 | 之前 | 之后 |
|---|---|---|
| `INSERT INTO identity_ip_mac_history`（批量插入） | 1,364 ms/次，最慢 4,033 ms | **90 秒窗口内无一条 >300 ms** |
| `read_model_runtime_state` 写入 | 90/100s | 约 66/100s |
| `commit` | 112/100s | 约 38–67/100s |
| `identity_ip_mac_history` 堆/索引未命中 | 26–28% / — | 23.9% / 8.7% |
| `identity_access_history` 堆未命中 | 58–71% | 51.5% |
| `endpoint_entities` 更新 | 约 460/分钟 | **1,104/分钟** |
| `ncu-184-router-pilot` live lane | 冻结（21,304,962 / 14:41:23） | **持续推进**（21,305,037 / 14:54:36） |
| `ncu-auth-redis` live lane | 562,953 | **563,553**，持续推进 |

死锁仍为 0，`/readyz=200`，无新增失败单元。**两条身份 live lane 至此全部解冻**，
这是第 14 轮以来第一次两车道同时推进。

仍然偏高：`account_identity_session_projection` 堆未命中 93.1%（1.4 GB 表，读取密集），
以及 `endpoint_inventory_projection_jobs` 积压仍在增长——后者与设备中心的列表页无关，
但会影响设备详情的清单完整度。

### 单行热点与建议性写入（2026-10-14，第 20 轮）

第 19 轮的收尾测量显示主插入已降到 300 ms 以下，但
`UPDATE shared_device_profile_runtime … WHERE singleton` 仍以 30 次/90 秒出现在慢日志里，
每次约 431 ms，而且 `pg_stat_activity` 同时有**四个后端阻塞在它的 `Lock/tuple`** 上。

关键判断：调用频率其实只有 0.33 次/秒，所以不是频率问题——**是它在投影事务内部执行**，
而投影事务可以跑数十秒，于是这一行的元组锁被长期持有，所有触及该物化器的车道都排队。

改动两步：
1. `publishSharedDeviceProfile` 先 `tx.Commit()`，再用独立短事务写这一行；信标失败只报错，
   不回滚已经提交的投影。
2. 新增 `(*PostgresStore).writeAdvisoryState`，用 `SET LOCAL synchronous_commit=off` 执行这类
   建议性写入——心跳与监控计数在崩溃时丢失没有代价，不值得为它付 228 ms 的 WAL fsync。

实测（发布 `2026.10.14-async-beacon1`）：锁等待采样 6/6 只剩 `Lock/advisory`；
90 秒慢语句计数 `commit` 39 → 20、该 UPDATE 39 → 12、`read_model_runtime_state` 12 → 6；
`endpoint_entities` 更新 1,370–1,634/分钟；两条 lane 均推进；死锁 0；
`processed_jobs` 计数继续增长（说明改用异步提交后计数没有丢）。

### 设备中心覆盖度的诚实口径（2026-10-14，第 20 轮实测）

五轮优化（第 14、16–17、18、19、20 轮）之后按第 13 轮的口径重新测量，这才是用户可感知的结果：

| 指标（76,699 台设备） | 第 13 轮 | 第 20 轮 |
|---|---|---|
| 近 1 小时内有更新 | 0 | 0（生产端已停采，必然为 0） |
| 近 24 小时内有更新 | 11,143（15%） | **27,257（35.5%）** |
| `last_seen` 接近生产前沿（>06:00） | 未测 | **21,349（27.8%）** |
| `endpoint_entities` 写入速率 | 约 460/分钟 | **1,370–1,634/分钟** |

覆盖度翻了一倍以上，方向正确，但**仍未达标**：`endpoint_inventory_projection_jobs` 积压
仍在增长，`account_identity_session_projection` 堆未命中仍 93.1%。要真正达到 AGENTS.md 的
容量基线，仍需处理事件量（前置决定）或彻底重构分析路径的写入成本
（如 `identity_ip_mac_history` 按天分区，约 15 GB 一次性重建）。

### 空写与投影脏标记：no-op 守卫（2026-10-14，第 21 轮）

第 20 轮结束时先按计划去查 `account_identity_session_projection` 的 93% 堆未命中，结果发现
**它当前根本不热**：`seq_scan=0`、`n_tup_ins=0`、`n_tup_upd=0`，70 秒慢语句窗口内没有一条
触及它。那个 93% 是重启窗口期的旧值。**结论：不要优化冷路径**，于是转向真正的积压源。

真正的问题在投影任务队列：`endpoint_inventory_projection_jobs` 有 58,348 条待处理、
最老的一条已等 26 小时；而消费端 lane **在正常跑**（约 2.8 任务/秒），只是**产生速度与
消费速度相当**，所以积压只涨不降。任务表本身很小（80,228 行 / 21 MB），瓶颈不在数据库。

根因排查落到两条最热的 upsert 上：它们都没有 `ON CONFLICT … WHERE` 守卫。PostgreSQL 会为
每个冲突行写入新元组版本、全部索引项并触发行级触发器，**即使新值与旧值完全相同**。于是：

- 重复/重放的事件是纯空写：新元组 + 索引 + WAL，约 7 张表的触发器白跑；
- 每次空写还会触发 `inventory_projection_change`，把该 endpoint 的投影任务重新标脏——
  这正是"消费追不上产生"的来源之一。

改动：给两条 upsert 加 `WHERE` 守卫，**每个谓词精确镜像 SET 中的一条赋值**，因此被跳过的行
一定是"存储值已经等于更新结果"的行。附带效果：`endpoint_entities.updated_at` 只在真正变化
时推进。

回归测试用 `xmin`（行版本）断言，而不是只看 `updated_at`——这才真正证明"没有发生写入"。

实测（发布 `2026.10.14-noop-upsert1`）：

| 指标 | 之前 | 之后 |
|---|---|---|
| `identity_ip_mac_history` 慢插入（>300 ms） | 12–69 次/窗口 | **2 次/60 秒** |
| `endpoint_inventory_projection_jobs` 积压 | 单调上升 | **58,420 → 58,418 / 120 秒（首次持平）** |
| `ncu-184-router-pilot` live | 21,305,112 | **21,329,612** |
| `ncu-auth-redis` live | 565,353 | **572,203** |

**口径提醒**：`endpoint_entities.updated_at` 的语义变了——no-op 不再推进它，所以
`entities_updated10min` 由"被触碰"变为"真的发生变化"（8,728/10 分钟）。数值下降是预期的，
不是回退；今后比较覆盖度请用 `last_seen` 分布，不要用 `updated_at`。

### 投影积压的真实原因：lane 反复失败，不是脏标记速率（2026-10-14，第 22 轮）

第 21 轮把积压从"单调上升"降到"持平"后，本轮把 no-op 守卫扩展到
`identity_access_history`、`account_sessions`（并修掉 `account_sessions` 后面那条会抵消守卫的
`policy_metadata` 更新）。但实测积压**又恢复增长**（+180/分钟），于是逐项排除了所有猜测：

| 猜测 | 实测 | 结论 |
|---|---|---|
| 脏标记产生太快 | 两条 lane 确实推进更快（ncu-auth-redis 576,203 → 650,453） | 是放大因素，但不是根因 |
| 任务领不到（门控） | 60,034 个待处理任务**全部** `contributions_ready=true`，60,033 个立即可领 | **不是** |
| 任务表太大/太慢 | 80,343 行 / 21 MB，`never_processed` 仅 46 | **不是** |
| 该 lane 的 SQL 慢 | 60 秒慢语句窗口内**没有一条**属于该 lane 的工作 | **不是** |
| **lane 正在失败** | `endpoint_inventory_projection_state.last_error='projection_failed'`，且每约 6 秒被重写一次（15:42:02 / 15:42:08 / 15:42:14）；92 个任务行带该错误 | **是** |

即：`endpoint_inventory_projection_jobs` 有 6 万个**立即可领**的任务，lane 的 SQL 也都不慢，
但它的吞吐只有约 0.8 任务/秒——因为它在反复失败。这解释了为什么"提高写入效率"无法让积压下降。

尚未解开的一点：该单元（`proxy-sentinel-inventory` / `-backfill`）的 journal 里近 30 分钟
**没有任何应用日志**，而代码在写 `projection_failed` 前会 `Fprintf(os.Stderr, "inventory
projection batch failed …")`。下一轮需要先解决"失败日志为何没进 journal"，再定位真正的错误
（很可能是一个具体的 SQLSTATE）。在此之前，不要再用"提高消费速度"的思路去猜这条积压。

### 第 22 轮结论的更正与实际修复（2026-10-14，第 23 轮）

**更正**：第 22 轮把 `endpoint_inventory_projection_state.last_error='projection_failed'`
当成"lane 正在反复失败"是错的。查日志才发现 3 小时内只有 5 条失败记录，且全部是
`sqlstate:57P01`（`admin_shutdown`，即我自己重启 PostgreSQL 的时刻）。该状态字是
`inventory_projection.go:343` **派生**出来的——

```sql
UPDATE endpoint_inventory_projection_state
SET last_error = CASE WHEN EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs
                 WHERE last_error<>'' AND processed_generation<dirty_generation)
                 THEN 'projection_failed' ELSE '' END,
    updated_at = now()
WHERE singleton
```

它每次运行都刷新 `updated_at`，所以看起来像"每 6 秒失败一次"。教训：**派生状态字不能当作
失败证据**，要看原始日志与 SQLSTATE。

**本轮把四个猜测逐一排除**：

| 猜测 | 实测 | 结论 |
|---|---|---|
| 任务领不到（门控） | 60,034 个待处理任务**全部** `contributions_ready=true`，60,033 个立即可领 | ✗ |
| 任务表规模 | 80,343 行 / 21 MB，`never_processed` 仅 46 | ✗ |
| 该 lane 的 SQL 慢 | 60 秒慢语句窗口内**一条都没有**（成本摊在大量小语句上） | ✗ |
| 陈旧错误标记被优先重试（`ORDER BY (last_error<>'')` 把它排在首位） | 清掉 92 个陈旧错误后吞吐**没有变化**（40–52 → 37–41/分钟） | ✗ |

**真正的限制是车道本身是顺序的**：`inventory_projection.go` 的 realtime 车道一次只处理一个
endpoint，吞吐被单 endpoint 的处理时间钉死在约 0.67 任务/秒，而脏标记以约 133/分钟产生。

**修复**：realtime 车道改为并发处理（`inventoryRealtimeWorkers()`，环境变量
`PROXY_SENTINEL_INVENTORY_REALTIME_WORKERS`，默认 2、范围 1..8，=1 可恢复原顺序行为），
连接池按 `2×workers+2` 放大（每个并发 endpoint 可能同时占用认领连接与事务连接）。

**实测**（发布 `2026.10.14-inventory-parallel1`）：

| 配置 | 吞吐 | 积压趋势 |
|---|---|---|
| 顺序（基线） | 40–52/分钟 | +93/分钟（稳定增长） |
| 2 workers | 63–102/分钟 | +26/分钟 |
| **4 workers** | **102–169/分钟** | 围绕 61,000 **震荡**（7 分钟净 +66，此前同长度窗口 +650） |

死锁 0、`/readyz=200`。**注意**：上游身份车道同步提速（`ncu-auth-redis` 650,453 → 868,204），
脏标记产生速率随之上升，因此积压没有单调下降。这条积压至此已从"吞吐上限问题"变成
"产生速率 ≈ 消费速率的速率问题"——下一步要减少每次变化的脏标记量（例如一次投影一个
endpoint 批次而不是单个 endpoint，或对短时间内的重复标脏做去抖），而不是再提高并发。

### 并发度实测与积压转为下降（2026-10-14，第 24 轮）

第 23 轮把 realtime 车道改为并发后默认只给 2 个 worker，本轮把旋钮逐档量了一遍。判断依据是
进程 CPU 只有 **5.5%**——它是 I/O 受限而非 CPU 受限，所以并发可以直接换成吞吐：

| `PROXY_SENTINEL_INVENTORY_REALTIME_WORKERS` | 吞吐 | 积压 |
|---|---|---|
| 1（原顺序实现） | 40–52/分钟 | +93/分钟 |
| 2 | 63–102/分钟 | +26/分钟 |
| 4 | 152–180/分钟 | +106/分钟（上游同步提速，脏标记速率升到约 271/分钟） |
| **8（现场设定）** | **242–308/分钟** | **−24/分钟（6 分钟净 −144）** |

8 workers 下：PG 连接 48、死锁 0、`/readyz=200`；设备中心覆盖度 `within24h` 44,557（55.8%）、
`near_frontier`（last_seen > 06:00）32,651；两条身份 lane 同时高速推进
（ncu-184-router-pilot 21,813,112、ncu-auth-redis 903,033）。

**注意默认值**：代码默认仍是 2（对小型部署保守），现场通过 `runtime.env` 设为 8。
在一个 CPU 空闲、I/O 受限的部署上，2 会明显低估机器能力——换环境时应按同一方法逐档量。
旋钮上限为 8；若要继续提高，需要先确认磁盘/PostgreSQL 是否仍是空闲的一方，而不是直接改大。

### 结论：生产已停、设备中心已追平前沿（2026-10-14，第 25 轮）

**生产确实已停**（四项独立证据）：`zeek-cluster` failed，`device-signal`/`suricata`/`discovery`/
`passive-discovery`/`ncu-identity-sync` 全部 inactive；近 60 分钟 **ingest 批次 = 0**；
`normalized_events` 行数 60 秒零变化；近 10 分钟 **`queue full` = 0**。

**归档已排空**：`ttl.jsonl` 124,325,110,008 B 与 `end_offset` 相等，剩余 0.0 MiB。

**磁盘图景反转**：ClickHouse 合并从每分钟 190+ MiB 降到 60 秒内 1 次 / 3.92 KiB，
而 postgres 成为最大写者（11 MB/s，此前 0.5 MB/s）——磁盘仍 ~90% 忙，但现在是 PostgreSQL
在做**有用的**积压排空。

**设备中心已追平前沿**（这是本问题最终要看的指标）：

| 指标 | 值 |
|---|---|
| 身份流最新事件时间 | `2026-10-14 08:39:45` |
| 设备中心 `max(last_seen)` | `2026-10-14 08:39:45` |
| **前沿滞后** | **0** |
| 近 1 小时有更新 | 25,772（32.3%） |
| 近 6 小时有更新 | 41,246（51.6%） |
| 近 24 小时有更新 | **51,593 / 79,877（64.6%）** |

对比第 13 轮实测（近 24 小时 11,143 / 15%、中位数约 2 天前），覆盖度提升约 4.3 倍。

**剩余身份追赶的性质已被查明，不是新鲜度缺口**：`ncu-184-router-pilot` 的 live 车道仍落后
约 25 小时，但这段 58.66M 行的积压**100% 是 `type='device'` 事件**（其中 58.29M 来自
`source='packet-sidecar'`），而这些设备状态早已由实时路径写入 PG（`endpoint_entities`
正是停在前沿 08:39:45）。加上第 21–22 轮的 no-op 守卫，重放这些事件不会改变任何数据——
它是**对实时路径丢批的持久化补偿**，不是设备中心滞后的原因。因此本轮**没有**为它做
时间分区并行化：那会花掉约 42 小时磁盘 I/O 却几乎不改变数据。当前该车道速率已从
约 19 事件/秒升到 **383–489 事件/秒（约 25×）**，可在后台自行排空。

设备清单投影积压同期从 61,453 降到 **59,685**，消费 225–300/分钟，仍在下降。

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
