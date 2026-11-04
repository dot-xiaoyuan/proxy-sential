# 识别重复唤醒：有界延后合并（2026-11-04，第二轮验收修订）

## 背景

r70 完成镜像发现 P0 排空后，识别待办在 11-04 上午持续净增：09:41 待办 21,583，09:50 前后 22,310；近 5 分钟完成约 641–739 个。任务无集中报错、无重试堆积，单任务平均约 300–360 ms，其中摘要写入约 271–321 ms。

发现投影的 `stream_discovery_device_state` 每小时更新约 40,502 行（01 时段），而 `endpoint_entities` 每小时只更新约 6,800 行。识别待办的增长与发现状态发布同步放大，说明大量唤醒没有带来新的识别输入。

## 根因

`mergeStreamDiscoveryFact` 对“内容完全相同、仅刷新观测时间”的重复观测返回 `Result=repeat_observation, WriteFact=true, VisibleChanged=false`（[stream_projection.go:208](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/discovery/stream_projection.go:208)）。投影随后对每个 `WriteFact` 的事实调用 `dirty.add(prior, next)`：

- `addRecognitionDirtyMACs` 只要任一侧存在 `recognition_fields` 就标记该 MAC；
- 对 `dhcp/dhcpv6/arp/ndp` 绑定事实，`dirty.add` 还会把 IP 作用域加入集合，触发 `streamRecognitionAffectedBindingsSQL` 查询该地址上的所有 MAC 并标记。

因此每次 ARP/DHCP 重复观测都会把地址作用域内的终端重新标记为识别脏，即使语义内容没有变化。Codex 的现场记录显示 stream3 前三段 92.7% 是 `repeat_observation`。

## 验收意见与修订

### 第一轮意见

首版候选直接跳过所有 `VisibleChanged=false` 的唤醒，验收指出这会漏掉必要更新：语义哈希排除了 `observed_at` 和 `valid_until`，而识别查询用它们筛选有效证据、按新近程度排序（[stream_recognition_postgres.go:40](/Users/yuantong/Developer/Projects/golang/proxy-sentinel/internal/store/stream_recognition_postgres.go:40)）。例如 DHCP 绑定过期后识别已重算，同内容的续租又使绑定重新生效；这次续租的唤醒不能被丢弃。

修订：可见变化立即唤醒；重复观测改为**有界延后合并**，窗口内合并为一次运行，窗口结束后必然有一次识别。

### 第二轮意见

1. 已有待办即使不需要增加代次，`ON CONFLICT` 仍无条件写 `updated_at=now()`；worker 按 `updated_at` 领取，重复观测会把待办反复推到队尾并放大写入。
2. 同一批次既有纠正又有重复观测命中同一终端时，先立即入队、再延后入队；若任务正被领取，后一步会把 `not_before` 改成 60 秒后。
3. 延后更新没有把历史任务的 `lane` 切回实时车道 `0`；历史 worker 停用时任务可能留在无人消费的车道。

修订：

- 延后 SQL 增加冲突更新条件，**跳过无需变化的待处理实时任务**：未领取、lane=0 的待办保持原行、原 `not_before`、原 `updated_at`，不产生写入。
- 发布函数先解析立即/延后两个集合的终端 MAC，**从延后集合中删除与立即集合重叠的终端**，立即路径优先；延后 SQL 不会再覆盖同批次纠正/撤销的调度。
- 冲突更新设置 `lane=0`，与现有 `mark_endpoint_recognition_dirty` 的实时车道接管语义一致；历史任务会被实时 worker 接管。

### 第三轮意见

1. **跨批次**：上一批重复观测建立的 `not_before=+60s` 待办，在下一批纠正/撤销时仍会被现有 `mark_endpoint_recognition_dirty` 跳过（它只处理已完成、已领取或 lane=1 的行），因此纠正仍要等到原窗口。
2. **PostgreSQL 回归**：测试先插入终端、再插入同一终端的任务；终端插入触发器已创建任务，第二次插入违反主键。

修订：

- 新增 `markStreamRecognitionDirtyNow`：先调用现有脏标记函数，再执行 `promoteDeferredRecognitionJobs`，把“待处理、未领取、lane=0、`not_before` 在未来”的实时任务提升为 `not_before=clock_timestamp()`，保留代次、`updated_at` 和队列顺序；投影的立即路径与过期路径都改走该入口。
- 集成测试改为 **UPDATE 触发器创建的任务** 布置状态；续租/延后场景先把任务置为已完成，再验证延后调度与跨批次提升。
- 立即提升排除识别失败后的重试退避：只提升 `attempts=0 AND last_error=''` 的任务，后续可见变化不会提前解除退避。
- 测试清理改为 `t.Cleanup`（先注册 `db.Close`、后注册行删除，LIFO 保证先删行再关连接），不再用会在 `t.Cleanup` 之前执行的 `defer db.Close()`。

## 变更

- `internal/discovery/stream_recognition_binding.go`：`routeRecognitionWake` 分流立即/延后；`resolve` 统一展开 IP 作用域；新增 `dropImmediateOverlap` 保证立即优先。
- `internal/discovery/stream_projection_db.go`：
  - 投影事务同时维护立即/延后脏集合；
  - `markStreamRecognitionDirtyDeferred` 使用集合式 `INSERT ... ON CONFLICT`，仅对“已完成 / 已领取 / lane=1”的任务递增代次、切回 lane=0 并调度到窗口后；等待中的实时任务不更新；
  - 窗口常量 `streamRecognitionRepeatCoalesceWindow = time.Minute`。
- 测试：
  - `stream_recognition_binding_test.go`：重复观测进入延后集合、**过期后同内容续租仍调度**、纠正/撤销立即、立即/延后重叠删除、延后 SQL 窗口参数；
  - `stream_recognition_deferred_integration_test.go`：需要 `PROXY_SENTINEL_TEST_POSTGRES_DSN` 的 PostgreSQL 回归，覆盖等待中实时任务不被改写、lane=1 接管、已完成/已领取任务延后调度，以及**跨批次纠正提升延后任务**。

## 验证结果

- `go test ./internal/discovery/ -count=1`：通过（含新增单元测试；PostgreSQL 回归在未设置 `PROXY_SENTINEL_TEST_POSTGRES_DSN` 时跳过）。
- `go vet ./internal/discovery/`：通过。
- `go build ./...`：通过。
- 延后 SQL 在 184 PostgreSQL 上以 `PREPARE` 校验语法通过（只做解析计划，未执行、未写入）。
- **PostgreSQL 回归已在 184 的隔离测试库实际运行**，分两次：
  - 完整迁移库 `ps_reg_20261104_1`（`CREATE DATABASE ... OWNER proxy_sentinel`，PostgreSQL 迁移至 `226_stream_discovery_current_page.sql`，258 张表）：`TestStreamRecognitionDeferredQueuePostgres` 与 `TestStreamRecognitionDeferredPromotionPostgres` 通过。
  - 加入退避排除后，用生产 DDL 子集的轻量库 `ps_regq_20261104_1`（`endpoint_entities`、`endpoint_recognition_jobs` 及 060/101/137 的函数与触发器）运行三条用例：

```bash
PROXY_SENTINEL_TEST_POSTGRES_DSN='...' /tmp/discovery.test -test.run 'TestStreamRecognitionDeferred|TestStreamRecognitionBackoff' -test.v
=== RUN   TestStreamRecognitionDeferredQueuePostgres
--- PASS: TestStreamRecognitionDeferredQueuePostgres (6.12s)
=== RUN   TestStreamRecognitionDeferredPromotionPostgres
--- PASS: TestStreamRecognitionDeferredPromotionPostgres (1.93s)
=== RUN   TestStreamRecognitionBackoffNotPromotedPostgres
--- PASS: TestStreamRecognitionBackoffNotPromotedPostgres (1.38s)
PASS
```

两个测试库的 `DROP DATABASE` 仍排队（现场 checkpoint 未完成），库暂时存在；未改动任何业务表；临时二进制与脚本已删除。

## 184 发布与短窗验收（2026-11-04）

- 本地集成分支已快进到 `9e58e0eb`；`go test ./internal/discovery -count=1` 与 `go vet ./internal/discovery` 通过。唯一候选包 `2026.11.04-recognition-wake-r71` 的 SHA256 为 `b1b37b1b6b606fd532b7b236b241ffda571185e0ba232f197731cbaab0118268`，发布清单记录该提交且工作区无未提交改动。
- 184 在 UTC 02:59:07 完成应用更新：`current=r71`，`previous=r70`。应用更新脚本核对 PostgreSQL 227 个、ClickHouse 63 个已应用迁移及校验值，未执行新迁移；发现 worker 实际运行 r71。按发布参数保留 inventory 服务；识别物化器仍固定 r24、NCU 身份物化器 r25、DHCP 逐消息流 r66、分钟影子 r59b。
- 切换后 `readyz=200`，发现投影继续提交段。识别队列在 UTC 03:00:07 至 03:01:07 的一分钟样本中，脏代次增加 82、已处理代次增加 27、待办从 25,832 增至 25,887；UTC 03:02:52 待办仍为 25,887。样本较短，仅说明链路继续运行，不能据此宣称积压已解决。
- 两个隔离测试库分别约 21 MB 和 7.9 MB，其 `DROP DATABASE IF EXISTS` 后台进程仍在等待 PostgreSQL checkpoint；截至 UTC 03:02，最近完成的 checkpoint 仍为 00:51:46。保留 DROP 任务继续等待，未为删除测试库重启业务数据库或改动业务表；清理完成前不得记为已删除。

## 验收建议（供 Codex）

1. **PostgreSQL 回归**：设置 `PROXY_SENTINEL_TEST_POSTGRES_DSN`（已应用迁移的隔离库）后运行：

```bash
go test ./internal/discovery/ -run 'TestStreamRecognitionDeferred|TestStreamRecognitionBackoff' -count=1 -v
```

覆盖：等待中实时任务 `updated_at`/`not_before` 不变；lane=1 任务被接管为 lane=0；已完成/已领取任务递增代次并调度到约 60 秒后；跨批次纠正提升延后任务；**失败退避（`attempts>0`/`last_error`）不被提升**。

2. **有效唤醒量**：用 `sum(dirty_generation)` 的 5 分钟增量衡量有效任务数；不要用待办/完成数代替新增速率，也不要把段内重复比例当成任务减少比例。

```sql
SELECT sum(dirty_generation) AS generations,
       count(*) FILTER (WHERE processed_generation<dirty_generation) AS pending
FROM endpoint_recognition_jobs;
```

3. **等待任务队列位置**：部署后观察 `processed<dirty AND lane=0 AND lease_until<now()` 的任务，其 `updated_at` 不应被重复观测刷新；`not_before` 应保持在首次调度时间。
4. **续租回归**：构造 DHCP 绑定过期后同内容续租，确认终端仍产生新的代次或延后任务；纠正、撤销仍立即处理。

## 现场附带观察

验收期间发现现场 PostgreSQL 自 2026-11-04 00:51 UTC 后没有完成过 checkpoint（约 1 小时 55 分钟），checkpointer 与 background writer 均在 `DataFileFlush` 上等待；两个临时测试库的 `DROP DATABASE` 都因此排队（库仍存在，已脱离会话等待）。这与识别写入耗时（约 321 ms/task）和 WAL 等待一致，属于现场磁盘 I/O 饱和问题，不在本次代码变更范围内，建议单独立项处理。

## 未包含项

- **DHCP 部分归档段**：`ReconcileBody` 仍只校验、不补写；本次未改归档/补写路径。需先核对原写入令牌与异步 flush 状态，再按受控流程处理。
- **路由游标**：`stream_router_recognition_state`、`stream_router_reset_recoveries` 仍为 0 行；恢复入口已存在（`proxy-sentinel router fresh-cutover|reset-recovery`），需按 PG224 受控恢复约束在核对门控后执行。
- **Suricata stale pid 循环**与**共享/风险单元停用**属于现场运维/配置项，未在本次代码变更中处理。
