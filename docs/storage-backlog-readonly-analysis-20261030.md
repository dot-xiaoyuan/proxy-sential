# 存储积压只读分析：NCU 认证派生、识别覆盖统计、发现投影

本文是对当前代码与 184 现场的一次只读分析，不修改代码、不写业务表、不切换服务、不做容量压测。现场数字是 2026-10-30 10:08—10:22（北京时间）的点样本，不能替代长期容量验收。运行版本以现场进程实际指向的发布目录为准：全站 `current` 仍是 `2026.10.29-stream-retry-r16b`；控制面、识别、设备列表固定在 `2026.10.29-ncu-purpose-r24`；NCU 物化服务已在 10:00—10:02 定向切到 `2026.10.29-ncu-archive-r25`。

## 结论摘要

**这三个积压都不是单点代码 bug。主因都是数据模型和处理模型在当前数据量、单块机械盘和现有 PostgreSQL 用法下必然遇到的容量边界；代码问题的作用是把设计瓶颈放大成“永不完成的重试”“捕获队列满退出”和“计数器永远不归零”。识别覆盖统计还叠加了一个发布组合问题：工作区里已有的退避修复没有进入现场运行的 r24 二进制。**

| 问题 | 主要性质 | 代码侧可确认的问题 | 设计侧可确认的问题 | 现场状态（10-30 10:08—10:22 采样） |
| --- | --- | --- | --- | --- |
| NCU 认证身份派生 | 设计容量为主，代码问题为辅；归档部分已由 r25 批量化处理，短时净消化 | 起点前就绪键不清理；归档/派生计数器不按固定起点区分；旧版 17 个不确定归档未修复 | 热会话表约 200 万行、11 个索引，单次会话写入 0.7—5.1 秒；旧归档每片段约 4.5 条事件却要 4 个 PostgreSQL 事务和 2 次 ClickHouse 请求 | 派生当前能跟上约 4 条/秒输入，但端到端 6—12 秒；新输入归档在 r25 后净消化；累计待归档 171,414 条中大部分是固定起点之前的旧批次（按批次粗算十几万条量级），消费者按起点过滤不会处理 |
| 识别覆盖统计 | 设计为主（每分钟重算 24 小时窗口）；发布组合为辅 | 三个刷新共用 20 秒预算，第三个任务被前两个挤掉；工作区退避修复未进入现场 r24 | 把 PostgreSQL 当每事件收据库，再用 `percentile_cont` 对 24 小时窗口反复聚合；收据分区约 1,126 万行、16 GB，且没有分区维护和保留任务 | `recognition-fresh-coverage` 最后成功是 2026-10-28 12:32 UTC，已陈旧约 37.6 小时；现场每 80 秒失败一次；采样时该分区 autovacuum 已运行 26 分钟 |
| 发现投影 | 设计为主（每事件账本写在 PostgreSQL/机械盘），代码把慢变成活锁和重启 | 整段一个事务，超时全部回滚；同一段无限重试、无上限、无退避、无死信；单 lane 队首阻塞；捕获入队与投影队列耦合，队列满即退出进程 | 一段 933—993 条事件要写约 933 个事件键、933 条收据、事实和变化行，再做 933 次随机主键探测；`stream_discovery_receipts` 约 16 GB/月、`stream_discovery_event_keys` 约 5.9 GB、`stream_discovery_changes` 约 4.7 GB；均无保留维护，收据分区也没有后续月度维护 | 66 个段未释放，最老 93 分钟，59 个超过 10 分钟；只有 projection lane 未确认；单个 933 条段反复在 8 秒超时；09:00 后已 3 次“passive spool queue full; capture stopped to expose data loss”退出，服务累计重启 636 次 |

一句话判断：

- **NCU 派生**：不是“派生逻辑算错了”，而是“会话当前态写在一个 5 GB、11 索引的热表上”。当前低输入下能追上，峰值会再次积压；归档的固定成本问题已经被 r25 的组批量化正面处理，现场出现净消化，但长期容量还没证明。
- **识别覆盖统计**：不是“统计口径错了”，而是“每分钟把 24 小时窗口重算一遍”的模型错了。数据本身是诚实的（读路径标 stale），但统计长期不可用，而且失败重试持续占用磁盘。
- **发现投影**：不是“某条 SQL 慢”，而是“每事件多行写入 PostgreSQL + 整段单事务 + 无限重试 + 捕获与消费队列耦合”的组合。它已经从延迟问题升级为捕获缺口和进程重启。

## 只读核对方法与边界

- 代码依据：工作区 `46ff5897`（`codex/stream-observation-performance-20261028`）；现场 r25 的归档批量化代码在 `37d64106` 与 `8bd5e067`（`codex/ncu-archive-group-20261029`），只读查看了提交和设计记录，没有合并或修改。
- 现场依据：`root@222.204.3.184` 的只读命令、`systemctl`/`journalctl`、`/var/lib/proxy-sentinel/stream-discovery-layered-r7` 的 journal 状态文件、PostgreSQL 只读查询和 `pg_stat_activity`/`pg_locks`。
- 没有执行：任何写表、迁移、服务切换、回填、备份、压测或页面登录验收。
- 一次 24 小时收据计数查询在 5 分 28 秒后仍未完成，已主动 `pg_cancel_backend` 取消；该查询本身给现场增加了并行读负载，本文不采用它的结果，也不重复执行。收据行数使用 `pg_class.reltuples` 估算并明确标注。

## 现场证据快照

| 指标 | 观测值 | 说明 |
| --- | --- | --- |
| 数据库总大小 | 158 GB | `pg_database_size` |
| 根盘 | 1.8 TiB，使用 89%，可用 203 GB | `df -h` |
| 数据盘 | `sda`，`ROTA=1`，ST2000NM000B | `lsblk`，机械盘 |
| 10:19 一秒 I/O | `sda` 读 8.1 次/秒、写 70.1 次/秒，`r_await` 6.54 ms，`%util` 0.89% | 该瞬间并不饱和；现场其它时段有 90% 以上利用率和数十毫秒等待的记录，I/O 竞争是 burst 型 |
| `account_sessions` | 5,092 MB（堆 2,401 MB），约 203 万行，11 个索引 | 最大单索引 `idx_sessions_endpoint_list_cover` 702 MB |
| `stream_discovery_receipts_202610` | 16 GB，约 1,126 万行（估算） | 月分区 |
| `stream_discovery_event_keys` | 5,951 MB，约 1,050 万行（估算） | 非分区 |
| `stream_discovery_changes` | 4,694 MB，约 354 万行（估算） | 非分区 |
| `identity_ip_mac_history` | 8,455 MB，约 1,384 万行（估算） | 代码中未发现保留清理 |
| `identity_ingest_batches` | 3,345 MB，约 137 万行（估算） | 载荷已回收，行和索引仍在 |
| 发现服务重启 | `NRestarts=636`（unit 生命周期累计）；09:00 后 3 次因队列满退出 | `systemctl`、`journalctl` |
| 识别覆盖最后成功 | 2026-10-28 12:32:01 UTC | 距采样约 37.6 小时 |
| 识别覆盖失败间隔 | 10:11:45、10:13:05、10:14:25……每 80 秒一次 | 20 秒查询超时 + 60 秒固定等待 |

## 1. NCU 认证身份派生

### 1.1 代码路径

新鲜输入先由主处理写权威事实并推进 `identity_ingest_batches.processed_offset`，片段末尾跨过后登记 `identity_derived_ready` 键；派生消费者按固定起点领取键，再读取片段正文，更新端点和会话，最后把片段标记为 `derived_state='completed'` 并释放暂存正文。关键代码：

- 领取与租约：[identity_derived_ready_claim.go](../internal/store/identity_derived_ready_claim.go#L45-L120)。先取最多 8 个到期重试键和 24 个新键，再按主键关联片段和批次，锁定片段；没有全局排序，r17 之后的领取路径本身是合理的。
- 派生应用：[identity_fragment_derived.go](../internal/store/identity_fragment_derived.go#L74-L160)。认证事件先单独提交端点事务，再在第二个事务里写会话和设备信号，最后完成片段。
- 会话写入：[identity_auth_projection.go](../internal/store/identity_auth_projection.go#L53-L120)。`WITH previous ... FOR UPDATE` 读取旧会话，再 upsert、记录离开设备、返回变化会话；`changedAuthenticationSessionsSQL` 在一个事务里完成。
- 会话列更新策略：[identity_fragment_session.go](../internal/store/identity_fragment_session.go#L24-L47)。`account_id`、`endpoint_id`、`ip`、`mac`、`updated_at` 等列都会变化。
- 归档：[identity_fragment_export.go](../internal/store/identity_fragment_export.go#L33-L115)。旧路径每片段领取一次，正文完成一次 PostgreSQL 事务，再领取一次做检索、再完成一次，共 4 个 PostgreSQL 事务和 2 次 ClickHouse 请求。

### 1.2 现场表现

10:15 前后的派生完成日志显示，端到端延迟约 6.3—11.8 秒，阶段耗时：

| 阶段 | 样本范围 | 说明 |
| --- | --- | --- |
| endpoint | 341—2,234 ms | 端点 upsert |
| session | 667—5,142 ms | 会话 upsert，仍是主要成本 |
| complete | 198—1,797 ms | 片段完成和提交 |
| apply 合计 | 2.9—7.1 秒 | 不含领取 |

10:11 的就绪队列只有 662 行，其中 **655 行固定在起点之前**（最老 2026-10-29 04:41 UTC），7 行在起点之后（02:11 UTC 附近）。655 行不会被领取，也不会被删除；这是切换时留下的“幽灵键”。状态发布器用固定起点过滤，所以 API 不会把它们报成新积压，但它们永久占用表和索引，也让任何直接查表的临时排查得出错误结论。

当前输入约 4.0 条/秒（02:16:00—02:17:30 接收 359 条），主处理与派生都能跟上；按“6 个消费者 × 每批约 10 条 ÷ 4.5 秒会话事务”粗算，上限不超过约 13 条/秒。这是**估算**，不是压测结论。含义是：现在不积压不代表白天高峰不积压，派生没有真正的容量余量。

### 1.3 归档侧：r25 已经改变了结论

旧归档路径的固定成本很重：现场平均每片段只有约 4.5 条事件（505 个起点后待办批次、2,293 条事件的样本），却要 4 个 PostgreSQL 事务、2 次 ClickHouse 持久确认和多次租约更新。r25 把同一作用域、同一归档月份的片段组成最多 32 片段 / 200 事件 / 1 MiB 的不可变组，每组仍最多 4 个 PostgreSQL 事务，但 ClickHouse 正文和检索各只发一次请求（设计记录在分支 `codex/ncu-archive-group-20261029` 的 `docs/ncu-archive-group-design.md`，当前工作区尚未合并该文件）。现场 10:00—10:02 完成 NCU 单服务切换（迁移 202 已在此之前应用），10:02:39—10:09:42 的 7 分钟样本显示接收 +1,515、归档 +13,385，累计差从 185,206 降到 173,336；起点后未完成批次从 9,787 降到 7,781。

本次 10:16:00—10:17:30 的 90 秒样本继续同向：接收 +359，归档完成 +2,615。这是计数器差，可能包含此前组的完成，不是恒定吞吐；但它足以说明 **“归档固定成本”这一设计问题已经被批量化正面处理，当前不是净增长**。

仍然存在的归档问题：

- `export_pending_records` 仍是 171,414，但 10:12 的精确计数显示，待办批次中 37,106 个在固定起点之前、6,903 个在起点之后；消费者按起点过滤，不会处理起点前的批次（其中也可能有批次状态滞后于片段完成的）。按样本 4.5 条/片段粗算，旧历史粗算为十几万条（14—17 万）量级；44,009 个批次的粗算总量高于 171,414，这提示批次状态与片段完成并不等价（也可能只是两类批次的平均大小不同），不能把这个估算当成精确分配。这个混合数字**不可能归零**，不能作为新输入积压的验收指标。
- 据 r25 切换记录，旧版 r24 留下 17 个 `archive_unconfirmed` 片段，r25 明确不把它们标成完成；需要逐项核对 ClickHouse 落点和原令牌后修复，不能直接重发或取消。
- r25 只在 NCU 物化服务上启用，尚未合入 `current` 分支；未来全站升级必须显式处理固定发布目录和覆盖文件，否则会退回旧路径。

### 1.4 判定

- **设计问题（主因）**：`account_sessions` 把“开放会话的当前态”和“已结束会话的历史”放在同一张约 200 万行、5 GB、11 索引的表里。PostgreSQL 的 HOT 只有在更新不修改任何索引列时才避免新索引项（[PostgreSQL HOT 文档](https://www.postgresql.org/docs/current/storage-hot.html)）；这里 `updated_at`、`endpoint_id`、`ip`、`account_id`、`mac` 都是索引列或表达式索引输入，每次会话写入都会在多个索引里产生新版本。机械盘上的随机索引页读写把“10 条会话”放大到数秒。本次没有逐事务锁等待采样，同一会话行锁等待也可能贡献，不能把 4—5 秒全部归因于磁盘。
- **代码问题（次因）**：起点前就绪键不清理、归档/派生计数器不按起点区分、旧版不确定归档没有修复入口。这些不制造主瓶颈，但让积压不可解释、无法归零。
- **不是代码问题**：派生领取的全局排序已经在 r17 消除，租约、乱序、结束优先等语义在代码和抽查中成立；把当前延迟归因于“领取 SQL 排序”已经不符合现场代码。

## 2. 识别覆盖统计

### 2.1 代码路径

后台循环在识别物化服务里启动（[recognition_materializer.go](../internal/store/recognition_materializer.go#L214-L216)），三件事共用一个 20 秒上下文（[fingerprint_coverage.go](../internal/store/fingerprint_coverage.go#L13-L37)）：

1. `flushFingerprintMatchCounts`
2. `refreshFingerprintCoverage`（来源覆盖，现场每分钟成功）
3. `refreshFreshRecognitionCoverage`（新鲜识别覆盖，现场持续失败）

第三步是核心：[recognition_fresh_observability.go](../internal/store/recognition_fresh_observability.go#L242-L305) 对 `stream_discovery_receipts` 最近 24 小时、`recognition_input IS NOT NULL` 的全部行做 `GROUP BY recognition_input->>'protocol'`，包含十几个 `FILTER` 计数、JSONB 字段提取、`avg` 和 `percentile_cont` 排序。结果整体写进 `read_model_runtime_state` 的一行 JSON。

读路径在 [fingerprint_coverage.go](../internal/store/fingerprint_coverage.go#L81-L94) 读取该快照；`as_of` 超过 3 分钟就标 `stale`。这是诚实的降级，但没有解决统计长期不可用。

### 2.2 现场表现

- `recognition-fresh-coverage` 的 `as_of` 是 2026-10-28T12:32:01Z，采样时已 37.6 小时；`fingerprint-source-coverage` 在 10:07 仍然正常更新，说明失败集中在第三步，而不是整个后台循环停摆。
- 识别物化服务日志每 80 秒出现一次 `fingerprint coverage update failed: timeout: context deadline exceeded`：20 秒查询超时 + 60 秒固定等待。
- 现场运行的识别物化服务是 r24（`/opt/proxy-sentinel/releases/2026.10.29-ncu-purpose-r24/bin/proxy-sentinel`），其源码 `f7f8fce` **不包含**工作区里的退避提交 `f498a719`。也就是说，代码仓库里“失败后 1→2→4→5 分钟退避”的修复没有进入现场运行的二进制；现场仍是每 80 秒重试一次（20 秒超时 + 60 秒固定等待）。这是发布组合问题，不是代码没写。
- 10 月收据分区约 1,126 万行 / 16 GB；采样时 `autovacuum: VACUUM public.stream_discovery_receipts_202610` 已运行 26 分 29 秒，持 `ShareUpdateExclusiveLock`，处于 `AioIoCompletion` 等待。它会与投影、识别统计争用同一块机械盘。
- 迁移 197 为窗口查询建了 `stream_discovery_receipts(accepted_at) WHERE recognition_input IS NOT NULL` 索引（[197_recognition_fresh_observability.sql](../migrations/postgres/197_recognition_fresh_observability.sql#L16-L18)），但索引只能减少扫描范围，不能避免对 24 小时窗口做聚合和排序。本次没有捕获该查询逐次的等待事件，20 秒超时是结果；窗口聚合、冷缓存和 autovacuum 竞争都可能是组成，不能只归因于 autovacuum。

### 2.3 判定

- **设计问题（主因）**：统计模型是“每次刷新重算完整窗口”，而不是“按分钟/协议增量维护，再合并出 1 小时/24 小时”。这直接违背项目自己的设备中心设计约束：“常用分类数量增量维护；复杂组合精确总数进入独立统计任务”（[device-center-storage-query-design.md](device-center-storage-query-design.md)）。窗口越大、数据越多，单次刷新越慢；数据增长不是线性可接受，而是直接超过 20 秒预算。
- **设计问题（存储侧）**：每事件收据行包含 `recognition_input`、`recognition_result`、`body_ref` 等 JSONB，月分区 16 GB。统计要反复读这些 JSONB，而 ClickHouse 已经保存了事件正文。把每事件识别结果长期放在 PostgreSQL 热表里，同时又要对它做窗口聚合，是把 OLTP 表当分析表用。
- **代码问题（次因）**：三个刷新共用 20 秒，前面两个成功也会消耗预算；失败重试没有区分“查询太大”和“数据库暂时不可用”；没有增量结果表，也没有部分结果。
- **发布问题**：退避修复在 `current` 分支，但识别服务固定在 r24，现场拿不到。仅部署退避只能把 80 秒一次降到 5 分钟一次，不能恢复统计；它应该和增量统计一起上线。
- **不是数据正确性问题**：读路径明确标 stale，没有把旧值伪装成新值；问题是无统计可用和持续无效负载。

## 3. 发现投影

### 3.1 代码路径

被动发现流把抓包写入 journal 段，三个 lane（archive、search、projection）各自消费。投影入口在 [stream_projection_db.go](../internal/discovery/stream_projection_db.go#L343-L500)：

1. `prepareStreamDiscovery` 对每条事件重新序列化、算 SHA256、构造收据和事实。
2. 开一个事务，先插入 `stream_projection_segments` 段标记。
3. `loadStreamDiscoveryReceipts` 用 933 个 `(scope,event_key)` 去 `stream_discovery_event_keys` 做 933 次主键探测（[L535](../internal/discovery/stream_projection_db.go#L535)）。
4. 加载事实版本、合并、写事实、发布设备状态、写变化。
5. `writeStreamDiscoveryReceipts` 插入 933 个事件键和 933 条收据（[L690](../internal/discovery/stream_projection_db.go#L690)）。
6. 提交。任何阶段超时，整个事务回滚，下一次从头再来。

lane 调度在 [cmd/discovery-worker/stream.go](../cmd/discovery-worker/stream.go#L173-L217)：每个 lane 一个 goroutine，严格按队列顺序处理；失败后 `DrainLane` 同一个段，200 毫秒后重试，永不放弃（L181—L205）。`SinkTimeout` 3 秒、`ProjectionRetryTimeout` 8 秒（L37）。

抓包与消费是耦合的：`CaptureStreamConfigured` 的 persist 在 journal 追加后调用 `onSegment`，后者向三个容量 64 的 channel 入队（[L225-L234](../cmd/discovery-worker/stream.go#L225-L234)）；投影队列满时 `onSegment` 阻塞，`drainSpoolQueueBounded` 阻塞，抓包侧 256 个槽位的队列被填满，`flush` 直接返回 `passive spool queue full; capture stopped to expose data loss`（[capture_linux.go](../internal/discovery/capture_linux.go#L104-L119)），进程以状态 1 退出。

journal 侧还有重复成本：[journal.go](../internal/streamlog/journal.go#L319-L404) 每次 `load` 都读取并 JSON 解码整段，再 `contentHash` 重新序列化整段计算哈希；`DrainLane`、`FinalizeAfterLanes`、`Release` 各会触发多次。一个 1.26 MB、933 条的段在一次投影生命周期里被反复解码和哈希。

### 3.2 现场表现

- 活动 journal `/var/lib/proxy-sentinel/stream-discovery-layered-r7` 有 66 个未释放段，最老接收于 2026-10-30 00:42:16 UTC（08:42 CST），采样时 93 分钟；59 个超过 10 分钟。
- 应用 ack log 后，66 个段中只有 projection 未完成：65 个 `projection=pending`，1 个 `projection=attempted`；archive 和 search 都已 acked。瓶颈非常集中。
- 投影反复卡在同一个段。以 485a…（933 条）为例：`validate` 0.1 秒、`insert_segment` 0.15 秒、`load_receipts` 7.6—7.8 秒，随后 8 秒超时；换段后 `write_receipts` 也会达到 7.6 秒。日志中 `reconcile duration=8.001s` 与 200 毫秒后的再次尝试连续出现。
- 10:17:30 一个段在 `write_receipts` 5.2 秒 + `commit` 0.23 秒后完成，说明并非所有段都必然失败；但成功一次之后，下一个 981 条段又会在 3 秒写入预算处超时。成功和失败都在同一资源边界上抖动。
- 10:17:31 出现 `passive spool queue full; capture stopped to expose data loss`，服务退出并在 10:17:41 重启；09:00 后已出现 3 次，`NRestarts=636`（unit 生命周期累计）。这不是“投影慢一点”，而是捕获链路在丢数据后主动退出。
- 数据库侧：`stream_discovery_receipts_202610` 16 GB / 约 1,126 万行、`stream_discovery_event_keys` 5.95 GB / 约 1,050 万行、`stream_discovery_changes` 4.69 GB / 约 354 万行。迁移 174 只为后两者建了保留索引（[174_stream_discovery_projection.sql](../migrations/postgres/174_stream_discovery_projection.sql#L26-L26)、[L162-L163](../migrations/postgres/174_stream_discovery_projection.sql#L162-L163)），但代码中没有任何删除或分区维护；收据分区只在迁移时创建了当时前后各两个月（含当月共 5 个，[L42-L52](../migrations/postgres/174_stream_discovery_projection.sql#L42-L52)），2027 年 1 月以后会落到 default 分区。
- 采样时 `autovacuum` 正在清理 1,126 万行的收据分区，投影的 `INSERT INTO stream_discovery_event_keys` 在 `DataFileRead` 上等待 7.25 秒。慢不是单一 SQL 的问题，是同一块盘上的随机读写和清理互相挤压。
- 需要区分“自然耗时”和“预算耗尽”：`load_receipts`/`write_receipts` 的 7.6—7.8 秒非常接近 8 秒预算，可能是查询在预算耗尽时被取消，而不是自然完成；同一次核对也有 5.8 秒完成的样本。能确认的是工作经常落在预算边缘，不能把 7.7 秒当成每条 SQL 的固定成本。采样时 `pg_locks` 未发现投影表上的冲突锁，`pg_stat_activity` 对同事务的 `event_keys` 插入显示 `DataFileRead` 等待，证据更支持 I/O 饥饿而不是行锁死锁。

### 3.3 判定

- **设计问题（主因）**：PostgreSQL 被当作“每事件账本”：每条事件至少写一个事件键、一条收据、可能一条事实、可能一条变化，再更新设备状态；每张表还有多个索引。933 条事件就是数千行随机写入加 933 次随机主键探测。机械盘上这是一次几秒级的随机 I/O 事务，而系统给它的预算是 3 秒写入、8 秒核对。数据量越大，单段成本越高；这不是调大超时能解决的。
- **设计问题（生命周期）**：事件键、变化表没有保留策略；收据分区没有月度维护。按当前 1,126 万行/月、16 GB/月的速度，表和索引会持续膨胀，投影的随机探测和 autovacuum 成本只会更高。这与 AGENTS.md 的“热查 30 天、归档一年、重复原文不因期限获得保留理由”不一致。
- **代码问题（放大器）**：
  - 整段一个事务，超时全部回滚，没有分段进度；一次 8 秒失败会把事务内已经写入的约 900 条工作全部回滚。
  - 同一段无限重试，没有次数上限、没有指数退避、没有死信/隔离；失败重试本身又写 WAL、又占 I/O，形成正反馈。
  - 每个 lane 一个 goroutine、严格 FIFO，队首段失败会阻塞该 lane 的所有后续段（head-of-line blocking）。
  - 捕获入队与 lane 队列容量耦合；投影队列满会让抓包 fail-fast 退出，把“消费慢”升级为“采集缺口 + 重启”。
  - 3 秒写入预算小于观测到的 5—7.8 秒阶段耗时；8 秒核对预算也多次被 7.6—7.8 秒阶段耗尽。预算边界与真实成本不匹配。
  - 段加载反复解码/哈希整段，放大了 CPU 和页缓存压力，但不是主因。
- **运维/容量**：单块机械盘、158 GB 数据库、16 GB 月分区、autovacuum 与投影/识别/NCU 共享 I/O。这些不是“代码错”，但决定了同样的代码在 SSD 上可能表现完全不同；不能把机械盘上的容量结论外推到其它硬件。

## 4. 三个问题的共性

1. **写放大**：PostgreSQL 里每事件多行、每行多索引；`account_sessions` 的更新几乎不可能 HOT；发现收据和事件键把正文之外的元数据又写了一遍。
2. **没有“有界进展”**：投影整段一个事务，失败就全丢；NCU 旧归档每片段固定 4 个事务；覆盖统计每次重算整个窗口。三者都没有“做完一小段就持久记录”的检查点。
3. **重试没有预算**：投影无限重试同一段；覆盖统计每分钟重试同一个大查询；NCU 旧归档失败后重试整个片段。缺少重试上限、退避、抖动、死信和降级。
4. **队首阻塞**：投影 lane 是单 goroutine FIFO；一个慢段挡住所有后续段。NCU 的领取已经做了“重试优先 + 新键优先”，但投影没有对应设计。
5. **生命周期缺失**：发现事件键/变化表无保留，收据分区无维护；身份地址历史无清理；这些表最终会成为新的“历史积压”。
6. **版本组合**：控制面、识别和设备列表固定在其 r24 发布目录，`current` 在 r16b，NCU 在 r25；工作区里的覆盖退避修复没有进入 r24。只改 `current` 不会改变固定路径的服务，反过来，固定路径的服务也可能缺少 `current` 分支的修复。

## 5. 大厂在海量数据下怎么做

下面的引用只用于说明成熟做法和边界，不表示本项目要照搬组件。项目约束仍是 PostgreSQL 控制面 + ClickHouse 事件/分析存储，不新增消息队列；重点是改变数据模型和处理模型。

### 5.1 写入路径：日志/列存承担每事件，OLTP 只留当前态

- Discord 把消息从 177 个 Cassandra 节点迁到 72 个 ScyllaDB 节点，迁移峰值 320 万条/秒，历史消息 p99 从 40—125 ms 降到 15 ms。它的关键不是“换数据库”本身，而是承认热分区、读放大和尾部延迟会拖垮整簇，并用 shard-per-core、请求合并和一致性哈希路由把热点隔离（[How Discord Stores Trillions of Messages](https://discord.com/blog/how-discord-stores-trillions-of-messages)）。
- Notion 的触发点很具体：PostgreSQL 的 `VACUUM` 开始持续卡住，磁盘 I/O 成为瓶颈；他们按至少 60K IOPS、单表 500 GB、单库 10 TB 设计，最终做成 480 个逻辑分片 / 32 个物理库，并用双写、审计日志、回填、暗读完成迁移（[Herding elephants: Lessons learned from sharding Postgres at Notion](https://www.notion.com/blog/sharding-postgres-at-notion)）。
- Uber 的 Kafka 分层存储方向是把热数据留在 broker、把较冷的数据下沉到对象存储，避免全部历史都占热路径（[Introduction to Kafka Tiered Storage at Uber](https://www.uber.com/blog/kafka-tiered-storage/)）。

对本项目的含义：**每事件收据、事件键、变化行不应该继续堆在 PostgreSQL 热表里**。更合适的分工是 ClickHouse 保存一份权威正文和可聚合的窄列，PostgreSQL 只保留当前事实、段级回执、未完成缺口和小型去重账本。若短期不能迁移，至少要先做批量写入、减少每事件行数和索引、按月份分区并加保留。

### 5.2 统计：摄入时预聚合或增量聚合，而不是反复扫窗口

- Druid 的 rollup 在摄入时按时间粒度和维度预聚合，官方说明可以把行数降低“orders of magnitude”，代价是失去逐事件查询能力；需要逐事件时另建一个明细数据源（[Apache Druid: Data rollup](https://druid.apache.org/docs/latest/ingestion/rollup/)）。
- ClickHouse 的 `AggregatingMergeTree` 保存中间聚合状态，后台合并时合并状态，而不是每次查询重算原始行；物化视图可以在写入时把原始行转成聚合行（[AggregatingMergeTree](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/aggregatingmergetree)）。

对本项目的含义：识别覆盖应该按“分钟 × 协议”维护计数、耗时直方图或可分位合并的摘要，再合并出 1 小时/24 小时；读接口只读快照并带 `as_of`。24 小时窗口的 `percentile_cont` 不应每分钟对原始收据重算。若继续用 PostgreSQL，也应建增量结果表，而不是把整个窗口塞进一行 JSON。

### 5.3 去重、幂等与恢复：稳定 ID + 检查点/重放

- Flink 的容错是“流重放 + checkpoint”：checkpoint 记录每个输入流的位置和算子状态，恢复时从 checkpoint 重放，从而得到 exactly-once 语义（[Stateful Stream Processing](https://nightlies.apache.org/flink/flink-docs-stable/docs/concepts/stateful-stream-processing/)）。
- Google Dataflow 的 exactly-once 依赖稳定事件身份和持久去重状态；处理函数可能执行多次，外部副作用仍要自己保证幂等（项目文档已引用该结论，见 [Google Dataflow: Exactly-once](https://cloud.google.com/dataflow/docs/concepts/exactly-once)）。
- AWS 的幂等重试要求稳定请求标识和语义一致的结果；超时后先核对未知写入，不凭超时重新生成身份（[Making retries safe with idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/)）。

对本项目的含义：投影不应“整段成功或整段重来”，而应把段切成可提交的块，每块有稳定键和完成标记；重放只重做未确认的块。事件键、段哈希和原接收时间已经具备，缺的是**块级检查点**，不是新的队列。

### 5.4 过载与重试：预算、退避、抖动、隔离、死信

- Google SRE 的过载处理给出三条直接适用的规则：每请求最多 3 次尝试；每客户端重试比例低于 10%；重试要带抖动，避免同步重试风暴。队列应有界，过载时早失败、便宜失败，并通过降级/丢弃低优先级工作保护核心路径（[Handling Overload](https://sre.google/sre-book/handling-overload/)）。
- 级联失败一章指出：请求超时后重试会造成“做了的工作被浪费、客户端再重试、负载更高”的正反馈；队列过长会让延迟和内存一起恶化；应该用 deadline、负载丢弃、按 keyspace 限制在途请求（[Addressing Cascading Failures](https://sre.google/sre-book/addressing-cascading-failures/)）。

对本项目的含义：当前投影正是这个正反馈——8 秒超时回滚、200 毫秒后重试同一段、每次重试重新写键和收据，负载越失败越高；捕获队列满后进程退出，又把恢复成本加回来。必须先有**重试上限 + 退避 + 隔离/死信 + 捕获解耦**，再谈吞吐。

### 5.5 PostgreSQL 的边界：HOT、VACUUM、SKIP LOCKED

- HOT 只在更新不修改任何索引列时才避免新索引项；`account_sessions` 的 `updated_at`、`endpoint_id`、`ip`、`account_id`、`mac` 都被索引或表达式索引引用，所以每次会话写入都要写多个索引（[Heap-Only Tuples](https://www.postgresql.org/docs/current/storage-hot.html)）。
- `VACUUM` 回收死元组、更新可见性地图；它会制造大量 I/O，且 `VACUUM FULL` 需要 `ACCESS EXCLUSIVE` 锁。对高更新表，应该更频繁地标准 VACUUM、调 `fillfactor`，而不是等膨胀后重写（[Routine Vacuuming](https://www.postgresql.org/docs/current/routine-vacuuming.html)）。
- `SKIP LOCKED` 适合“队列式表”的并发消费者，但它提供的是不一致视图，不是通用查询语义；队列表仍应尽量小、分区、按时间有序，而不是把百万级历史留在同一条领取路径上（[PostgreSQL SELECT](https://www.postgresql.org/docs/current/sql-select.html)）。

对本项目的含义：`account_sessions` 需要“当前开放会话”和“已结束历史”分离，或至少按状态分区；热表索引要精简，`updated_at` 这类每次变化的时间列是否必须建索引要重新核对。发现侧则要把“当前事实/状态”和“每事件账本”分开，后者不应继续用热 OLTP 表承担。

把上面的做法映射到这三个问题：

| 大厂做法 | 对应本项目问题 | 可以借鉴的部分 | 不能照搬的部分 |
| --- | --- | --- | --- |
| Discord 的热分区隔离、请求合并、shard-per-core | `account_sessions` 热表、发现投影热点 | 把热点键隔离，减少重复读；对同一键的并发请求合并 | 不需要因此更换数据库；当前问题是行放大和索引成本 |
| Notion 的 VACUUM/IOPS 触发分片 | 158 GB PostgreSQL、机械盘、autovacuum 竞争 | 先量化 IOPS 和单表上限；按时间/状态分区；把历史移出热路径 | 现在不必做 480 分片；先做表内分区和生命周期 |
| Uber 的 Kafka 分层存储 | 收据、事件键、变化表的无界增长 | 热/冷分层，冷数据下沉，热表只留查询窗口 | 不引入 Kafka；ClickHouse 已经承担正文和可聚合存储 |
| Druid rollup / ClickHouse AggregatingMergeTree | 识别覆盖的 24 小时窗口重算 | 摄入时或分钟级增量聚合，查询只合并小结果 | 不能因此丢掉逐事件证据；明细仍在 CH，聚合只是派生 |
| Flink checkpoint / Dataflow exactly-once | 发现投影整段重试 | 稳定键 + 块级检查点 + 重放未确认块 | 不需要 Flink；journal 已有持久位点和 ack |
| Google SRE 的重试预算、负载丢弃、队列管理 | 投影无限重试、捕获队列满退出 | 重试上限、退避、抖动、死信、捕获解耦 | 不能静默丢数据；丢弃必须有缺口记录和可见状态 |
| PostgreSQL HOT/VACUUM/SKIP LOCKED | 会话表 11 索引、热更新、队列式表 | 索引瘦身、fillfactor、分区、避免百万级历史留在领取路径 | 不能把普通 OLTP 表当无限增长的队列 |

需要强调：**换存储引擎本身不是答案**。Discord 和 Notion 的经验都说明，热分区、读放大、VACUUM 和 I/O 是数据模型和访问模式的问题；把同样的“每事件多行、整段一事务、无限重试”搬到 ClickHouse，仍然会产生过多小写入和过多重复计算。先修正数据模型和处理边界，再决定哪些表留在 PostgreSQL、哪些迁到 ClickHouse。

## 6. 建议的处置顺序（只读分析，不含实施）

### P0：先止住发现投影的活锁和捕获缺口

1. **解耦捕获与 lane 队列**：`onSegment` 不应在捕获线程里阻塞等待三个 lane 队列；改为由 dispatcher 从 journal 的未完成状态拉取，或让 `onSegment` 只做非阻塞投递并把段留在 journal，队列满时暂停投递但不退出进程。验收信号：不再出现 `spool queue full` 退出，捕获统计能明确显示暂停/恢复，而不是“丢数据后重启”。
2. **段内分块提交**：把 933—993 条段切成约 100—200 条的事件块，每块独立提交并记录块进度；超时只重做当前块。保留段级 `content_sha256`、原接收时间和幂等键。验收信号：一次 8 秒超时不再丢弃整段，队列年龄持续下降。
3. **重试预算和隔离**：同一段最多 N 次（例如 5 次）后进入可见的 `repair_required`/死信状态并让出 lane；退避带抖动；不让一个段永久挡住后续段。验收信号：单个坏段不再造成整条 lane 停止，积压可解释。
4. **减少每事件随机 I/O**：把收据/事件键写入改为批量、按主键排序；用 `INSERT ... ON CONFLICT ... RETURNING` 减少“先查全部再插入”的探测；评估把事件键/收据迁到 ClickHouse，PostgreSQL 只保留段级回执和当前事实。验收信号：同样段大小的 `load_receipts`/`write_receipts` 从秒级降到百毫秒级。
5. **只在这些改动之后**再考虑调大 3/8 秒预算；单独调大只会让失败事务占用资源更久，不能产生有界进展。

### P0：把识别覆盖改成增量统计

1. 新建按“分钟 × 协议”的增量结果表（或 ClickHouse `AggregatingMergeTree`），在收据写入/识别完成时累加计数、耗时摘要和分位摘要；1 小时/24 小时由小窗口合并，不再扫原始收据。
2. 读接口只读快照，带 `as_of`、窗口和统计版本；超过阈值标 stale，不回退到全量扫描。
3. 删除/停用每分钟的 24 小时聚合；保留一次性回填用于初始化，回填必须有界、可中断、记录缺口。
4. 把工作区已有的退避修复（`f498a719`）纳入现场运行的识别服务；但它是降载措施，不是统计修复。
5. 验收信号：`as_of` 在 2 分钟内；刷新耗时稳定在秒级；失败不再每 80 秒打一次全窗口查询。

### P1：NCU 派生和归档的剩余问题

1. **计数器按固定起点区分**：把“新输入待归档/待派生”和“起点前历史残留”分开计数；当前 171,414 不能作为新输入积压指标。验收信号：新输入待办可独立归零，旧历史残留单独展示为“已取消/未处理”。
2. **清理幽灵键**：655 个起点前的 `identity_derived_ready` 行按审计边界标记取消并删除，保留原始证据和原因；不要让不可领取的行永久占表。
3. **修复 17 个 `archive_unconfirmed`**：逐项核对 ClickHouse 落点、原令牌和哈希，确认存在则完成，缺失则保留缺口；不重发不确定写入。
4. **会话写入减负**：优先评估“开放会话/历史会话分离”或按 `ended_at` 分区，热表只保留开放会话；核对并删除零扫描索引（现场 `account_sessions_ip_lookup` 237 MB、`account_sessions_account_recent_tag` 288 MB 的扫描计数为 0 或个位数，但统计窗口可能被重置，删除前必须验证更长窗口和读路径）；再评估批量大小和连接数。验收信号：同样 10 条事件的 session 阶段从 4—5 秒降到亚秒级，峰值输入下队列不持续增长。
5. **保留 r25 的组批量化**，观察长期净消化；不要因为 90 秒净减少就宣布容量通过。

### P1：补生命周期，避免下一个积压

- 为 `stream_discovery_receipts` 增加月度分区维护（提前建未来分区，按热窗口 detach/drop，归档前核验引用和哈希）。
- 为 `stream_discovery_event_keys`、`stream_discovery_changes` 增加有界保留任务（30 天热查、一年归档；案件引用独立保护），并说明读取收益、写入成本和失效机制。
- 核对 `identity_ip_mac_history`（约 1,384 万行/8.4 GB）的读取方和保留责任，按 AGENTS.md 的热/归档模型补清理；不能直接删除唯一历史。
- 调整 autovacuum 对大分区的成本参数，避免 26 分钟的全分区清理与实时投影争 I/O；这是缓解，不是替代数据模型改造。

### P2：发布组合和可验证性

- 统一“固定发布目录”的服务清单：control-plane、inventory、recognition、NCU 各自指向哪个版本，哪些修复在 `current` 但不在固定目录；在升级清单里显式核对。
- 为三条链路分别暴露“新输入待办、最老时间、重试次数、死信/修复数、捕获暂停次数、统计 as_of”，并区分旧历史残留；不要让一个混合计数器承担验收。
- 任何容量结论必须附硬件、数据分布、输入速率、并发和观察窗口；当前机械盘上的短样本不能外推。

更完整的架构级方案（流式总线、热状态、ClickHouse 账本、预聚合和分阶段迁移）见 [高性能流式存储与投影方案](high-performance-streaming-architecture-20261030.md)。

## 7. 判定表：代码问题还是设计问题

| 问题 | 设计问题 | 代码问题 | 运维/发布问题 | 结论 |
| --- | --- | --- | --- | --- |
| NCU 派生延迟/峰值容量 | 热会话表 200 万行、11 索引；开放/历史混存；机械盘随机 I/O | 起点前键不清理；计数器不按起点区分 | 固定发布目录导致修复不进运行服务 | 设计为主，代码为辅；不是派生语义错误 |
| NCU 归档积压 | 旧路径每片段固定 4 事务 + 2 次 ClickHouse；片段平均仅 4.5 条 | 旧版 17 个不确定归档无修复入口；计数器混合旧历史 | r25 只在 NCU 服务启用，未合入 current | 设计问题已被 r25 批量化正面处理；长期容量未证明 |
| 识别覆盖统计 | 每分钟重算 24 小时窗口；PG 当每事件收据库；分区无维护 | 三个刷新共用 20 秒；无增量结果表 | r24 不含退避修复；autovacuum 与实时链争 I/O | 设计为主；发布组合放大了持续失败 |
| 发现投影 | 每事件多行写 PG + 933 次随机探测；整段单事务；无保留维护 | 无限重试、无上限/退避/死信；单 lane 队首阻塞；捕获与队列耦合；预算小于真实成本 | 机械盘、158 GB 库、autovacuum 竞争 | 设计为主，代码把慢升级为活锁、捕获缺口和重启 |

## 8. 未验证项与边界

- 没有做数据库隔离回放或并发压测；没有验证分块提交、批量写入、会话拆分等候选的真实收益。
- 没有精确统计 24 小时收据行数（查询已取消）；月分区行数是 `reltuples` 估算，不能当作精确值。
- 没有验证 `stream_discovery_receipts` 在 2027 年 1 月后的 default 分区行为；只从迁移代码确认没有自动建分区。
- 没有做页面验收、登录验收或前端三视口检查；本文不涉及前端改动。
- 没有宣称任何容量达标、历史追平或“问题已解决”。r25 的 7 分钟和本次 90 秒样本只证明短时净消化。

## 9. 参考

现场与代码：

- [NCU 身份派生定向处理记录](ncu-identity-derived-20261029.md)
- 分支 `codex/ncu-archive-group-20261029` 的 `docs/ncu-archive-group-design.md`（当前工作区尚未合并）
- [认证关系处理边界](ncu-authentication-projection-design.md)
- [当前工作与下一步](current-work-20261031.md)
- [设备中心存储与查询设计](device-center-storage-query-design.md)
- [新鲜事件存查的性能研究](stream-ingest-performance-research-20261028.md)

外部实践：

- [How Discord Stores Trillions of Messages](https://discord.com/blog/how-discord-stores-trillions-of-messages)
- [Herding elephants: Lessons learned from sharding Postgres at Notion](https://www.notion.com/blog/sharding-postgres-at-notion)
- [Introduction to Kafka Tiered Storage at Uber](https://www.uber.com/blog/kafka-tiered-storage/)
- [Apache Druid: Data rollup](https://druid.apache.org/docs/latest/ingestion/rollup/)
- [ClickHouse AggregatingMergeTree](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/aggregatingmergetree)
- [Apache Flink: Stateful Stream Processing](https://nightlies.apache.org/flink/flink-docs-stable/docs/concepts/stateful-stream-processing/)
- [Google Dataflow: Exactly-once](https://cloud.google.com/dataflow/docs/concepts/exactly-once)
- [AWS: Making retries safe with idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/)
- [Google SRE: Handling Overload](https://sre.google/sre-book/handling-overload/)
- [Google SRE: Addressing Cascading Failures](https://sre.google/sre-book/addressing-cascading-failures/)
- [PostgreSQL: Heap-Only Tuples](https://www.postgresql.org/docs/current/storage-hot.html)
- [PostgreSQL: Routine Vacuuming](https://www.postgresql.org/docs/current/routine-vacuuming.html)
- [PostgreSQL: SELECT / SKIP LOCKED](https://www.postgresql.org/docs/current/sql-select.html)
