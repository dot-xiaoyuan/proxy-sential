# 204 单盘图表写入执行方案

本文是 2026-11-18 复核后的执行说明。现场数字来自当日只读检查，活动版本为 `2026.11.18-615a18c1.3`。后续现场数以当次只读检查为准，不把短窗写成容量验收。

代码改动只做第 1、2 步，没有新迁移。分区删除和索引重建不放进安装包，等第 1 步验收后再单独执行。

## 顺序

1. 5 分钟桶只在关闭后写一次。先把实时插入从每 10 分钟约 64 次整桶重写降下来。
2. 小时和天汇总去掉连续 5 分钟的恢复条件，一次只领一个任务，从最老的小时开始追。
3. 确认 11 月 9 日分区已经整段超过 8 天 TTL 后，只删除这一个分区。
4. 对三张索引明显大于堆的小表逐个做 `REINDEX CONCURRENTLY`。
5. 新版本验收后，只保留 `current` 和 `previous`。

第 2 步依赖第 1 步。小时任务要读 5 分钟事实表，必须等实时整桶重写降下来再放行。第 3、4 步依赖第 1 步验收，避免在写入高峰上再加合并或建索引。

## 基线（2026-11-18 约 15:33，UTC 07:33）

| 项 | 复核结果 |
|---|---|
| 5 分钟事实表 | `activity_chart_facts_5m_v3` 6,194,075,054 行，119.89 GiB，活跃 part 1,538 个。11 月 18 日分区 986 个 part，最小 6 行 |
| 刚过去 10 分钟 | 增量比对 64 次，插入 64 次，写入 6,367,371 行，平均每次约 10 万行。比对平均 1.7 秒，P95 2.9 秒，读 7,610 万行 |
| 小时 / 天事实表 | 均为 0 行 |
| 小时任务 | `activity-hour-v3` 402 条，`processed_generation=0`，`attempts=0`。396 条已到期，最早 `2026-11-06 05:22:11Z`。其中 `campus_id` 为空 254 条 |
| 天任务 | `read_model_jobs` 中没有 `activity-day-v3`。天任务要等对应小时成功后才入队 |
| coarse | `proxy-sentinel-read-model-coarse.service` 自 13:30:41 起运行，journal 只有启动行 |
| 5 分钟水位 | 15:32 `as_of` 滞后 2 秒；约一分钟后同一条 `as_of` 未动，滞后 78 秒 |
| 过期分区 | `2026-11-09` 仍在，13.44 GiB、6 个 part。TTL 为 `bucket_start + 8 天` |
| 磁盘 | 已用 619G，空闲 1.1T，使用率 37% |
| 发布目录 | `current` → `2026.11.18-615a18c1.3`，`previous` → `.2`。同盘还有 `2026.11.18-615a18c1`、`2026.11.17-615a18c1`、`2026.11.16-8102ad51` |

`campus_id` 为空的小时任务保留并照常执行。5 分钟任务里空 campus 有 2,185 / 3,950 条，这是实际作用域。

## 明确不做

- 不把发现列表改到 `discovery_passive_device_current`。
- 不增加每批领取的协议源数量。
- 不缩短保留期，不删除唯一原文，不改已入账迁移。
- 不把 `activity_chart_facts_5m_v3` 改成 `ReplacingMergeTree`。该表已经约 120 GiB，在这块机械盘上重建会把盘打满。
- 不把 `ttl_only_drop_parts` 改成 1，不改 `merge_with_ttl_timeout`。
- 不对 `discovery_observations` 做 `VACUUM FULL`。它的 12GB 堆是 JSON，死元组约 2.6%。
- 不把 `discovery_observation_latest` 的 `observed_at`、`valid_until` 移出索引。列表的有效期过滤依赖这两列；移出后页内热更新也恢复不了。
- 不把本方案发布到 184。

## 第 1 步：关闭后的 5 分钟桶才插入

改 `internal/store/activity_v3_read_model.go`。

现在 `materializeActivityV3FiveMinuteAt` 在桶还开着时，只要维度或 `event_count` 变了就整桶 `INSERT`。`.3` 只跳过内容没变的桶，所以开着的桶仍然每次比对都插入。读者只用 `activity_chart_bucket_versions_v3` 里 `argMax(revision, published_at)` 的那一版。

目标行为：

- `now < bucket_start + 5 分钟 + 90 秒` 时，不插入、不分配 revision、不发布版本。把该任务的 `not_before` 推到 `bucket_start + 5 分钟 + 90 秒`，`dirty_generation` 保持大于 `processed_generation`，然后照旧调用 `updateActivityV3State`，避免 `as_of` 停住。
- 到点之后沿用现有比对。没有已发布版本，或维度 / 取值 / `event_count` 变了，才插入一次并发布。内容没变且尚未标成最终，只把现有 revision 标为最终并调用 `enqueueActivityV3HourParent`。
- 已关闭桶的晚到数据若改变计数，仍允许再插入一次。这条路径保留。
- 派发侧对未关闭桶不再使用 `openBucketRebuildDelay`（2 分钟）。未关闭桶的 `not_before` 直接设为关闭后 90 秒。已关闭桶仍用现在的 90 秒安静等待。

1 小时图里，当前这个还没关闭的 5 分钟桶会空着，关闭后再过约 90 秒出现。24 小时、7 天、30 天图的中间段读小时表和天表，不依赖这个进行中的桶。

`TestActivityV3QuietBucketSchedulesFinalization` 要保持这个结果：桶还开着时任务仍是 pending，且 `not_before` 不早于关闭后 90 秒；时钟拨到关闭后 90 秒再物化，只插入一次，并入队一个小时任务，`type` 维度合计为 1。补一个直接断言：开着的桶那一次调用没有往 `activity_chart_facts_5m_v3` 插入。

`TestActivityV3FiveMinuteDeltaSkipsUnchangedBuckets` 继续要求比对 SQL 含 `EXCEPT` 且本身不插入。

## 第 2 步：小时任务一次一个

改同一个文件的 `RunActivityV3Coarse`。

`activityV3RealtimeLag` 已经会在没有可执行的 5 分钟积压时返回 0。`TestActivityV3VerifiedIdleDoesNotStarveCoarsePostgres` 要求：未来才到期的收口任务不挡住小时汇总；已关闭却未收口的桶返回至少 90 秒滞后；心跳超过 30 秒必须报错。这些返回值保持不变。

要拆掉的是 coarse 循环里的额外条件：滞后不超过 60 秒必须连续保持 5 分钟才恢复。`as_of` 一两分钟才动一次，这段计时会被清掉，402 条小时任务因此一次都没被领取。暂停分支目前不写日志。

目标行为：

- `activityV3RealtimeLag` 返回错误，或滞后大于 90 秒：本轮不领取，暂停原因写入 stderr，并写入 `read_model_runtime_state` 里 coarse 自己的状态（原因、滞后秒数、时间）。同一原因不每 5 秒重复刷屏，状态行可以每次更新。
- 否则本轮最多领取 1 个 `activity-hour-v3` 或 `activity-day-v3` 任务。现有领取顺序保持不变：小时旧的在前。
- 两次成功领取之间至少间隔 30 秒。396 个不同小时不能在滞后刚降下来的几十秒里连续领完。
- 领取失败和物化失败继续写 stderr。
- 小时成功后入队天任务的现有 SQL 不动。天汇总读小时表，不读 5 分钟事实表。

空 campus 的任务不删除、不改键。

## 本地验证

在第 1、2 步的代码改完后执行：

```bash
gofmt -w internal/store/activity_v3_read_model.go internal/store/activity_v3_read_model_test.go
go test ./internal/store/ -count=1 -timeout 180s -run 'TestActivityV3|TestPassive'
go vet ./internal/store/ ./internal/discovery/
```

依赖独立 PostgreSQL 或 ClickHouse 的用例在没有 `PROXY_SENTINEL_TEST_POSTGRES_DSN` 时会跳过，报告里写明跳过，不把跳过写成通过。

## 发布

沿用 204 应用更新，不走带迁移的完整安装。控制面保持 `--read-only=true`，安装参数继续 `--skip-backup`。包内版本用日期加源码短哈希，外部文件名仍是 `proxy-sentinel-current.tar.gz`。

发布前只读核对：目标主机、`current`、`previous`、`proxy-sentinel-read-model-realtime` 与 `proxy-sentinel-read-model-coarse` 都在运行、磁盘空闲、迁移账本没有新的待执行文件。本方案不新增 PostgreSQL 或 ClickHouse 迁移。

切换后确认两个 read-model 进程的可执行文件都指向新发布目录。`upgrade-application.sh` 若没有重启 coarse，要单独重启它。`/readyz` 保持 200。

## 第 1、2 步的现场验收

切换后先看 10 分钟，再看小时任务是否开始动。查询都是只读。

5 分钟插入，在 ClickHouse 里：

```sql
SELECT count() AS inserts, sum(written_rows) AS rows
FROM system.query_log
WHERE event_time > now() - INTERVAL 10 MINUTE
  AND type = 'QueryFinish'
  AND query LIKE 'INSERT INTO activity_chart_facts_5m_v3%'
```

通过标准：插入次数接近这 10 分钟里实际关闭的桶数，而不是 64 次；写入行数相对基线的 637 万行下降数倍。若插入次数仍接近 64，停止第 2 步的追平，先查是否还有开着的桶在插入。

发现水位，在 PostgreSQL 里看 `passive_discovery_source_cursors` 的最慢时间与 `now()` 的差。通过标准：仍在约 2 分钟等待线附近。退回十几分钟就停止后续追平，保留现场进程，不放宽每批领取的源数量。

小时任务：

```sql
SELECT count(*) FILTER (WHERE processed_generation < dirty_generation) AS pending,
       count(*) FILTER (WHERE attempts > 0) AS attempted,
       min(updated_at) FILTER (WHERE attempts > 0) AS first_attempt
FROM read_model_jobs
WHERE model = 'activity-hour-v3';
```

通过标准：出现 `attempts > 0` 的行，并且 `activity_chart_facts_hour_v3` 的 `total_rows` 大于 0。抽一个已关闭小时，小时图一个维度的 `sum(event_count)` 等于该小时 12 个 5 分钟桶最新 revision 的合计。对不上就停止追平。

coarse 日志里能看到暂停原因或成功物化。磁盘用 5 秒 `iostat` 看利用率。这些数只说明这一窗，不作为容量验收。

追平期间保持一次一个、间隔不少于 30 秒。396 个小时跑完之前，不并行加 worker。天表会在对应小时成功后自行出现，不单独灌数。

## 第 3 步：删除已过期的 11 月 9 日分区

只在第 1 步验收通过后做。先只读确认这一分区的最大桶已经早于 8 天：

```sql
SELECT max(bucket_start) AS max_bucket,
       max(bucket_start) + INTERVAL 8 DAY < now() AS expired
FROM activity_chart_facts_5m_v3
WHERE toDate(bucket_start) = '2026-11-09'
```

`expired` 为真才执行：

```sql
ALTER TABLE activity_chart_facts_5m_v3 DROP PARTITION '2026-11-09'
```

11 月 10 日分区用同一判断，等到它自己的 8 天到期再删。不对其余分区执行 `OPTIMIZE FINAL`。

## 第 4 步：重建三张小表的膨胀索引

第 1 步之后先做 60 秒只读抽样，确认 `discovery_observations` 的更新速率仍接近每秒个位数，发现水位没有退回。然后列出这三张表每个索引的大小和扫描次数：

- `passive_census_identifier_current`：堆约 14MB，索引约 426MB，约 5.0 万行
- `discovery_observation_latest`：堆约 125MB，索引约 335MB，约 6.6 万行
- `passive_hardware_current`：堆约 35MB，索引约 154MB，约 1.6 万行

只对尺寸和行数不成比例、而且有扫描的索引用 `REINDEX INDEX CONCURRENTLY`，一次一个。做之前看磁盘利用率。`discovery_observations` 不重建整表。

`passive_hardware_facts` 和 `shared_device_profile_jobs` 若在这 60 秒里仍是每秒约 20 次更新，记到 `docs/current-work.md`，不放进这次发布。

## 第 5 步：旧发布目录

新版本按上面的标准验收，并核对进程、文件描述符、单元和挂载都不再引用更老的目录之后，删除：

- `/opt/proxy-sentinel/releases/2026.11.18-615a18c1`
- `/opt/proxy-sentinel/releases/2026.11.17-615a18c1`
- `/opt/proxy-sentinel/releases/2026.11.16-8102ad51`

保留 `current`（新版本）和 `previous`（`2026.11.18-615a18c1.3`，或届时的上一包）。清理结果写入现有发布退役审计目录。

## 错误码

`CANNOT_PARSE_INPUT_ASSERTION_FAILED`（27）和 `ILLEGAL_TYPE_OF_ARGUMENT`（43）在 15:33 仍在增加，近 10 分钟的 `system.query_log` 里没有这两类失败。第 1 步写入下降后，再从 `system.part_log` 和后台错误日志对一次来源。对不上用户查询之前，不改入库格式。

## 停止条件

出现任一情况就停在当前步骤，把实测数写回 `docs/current-work.md`：

- 5 分钟插入次数没有降下来。
- 最慢发现源落后重新超过 10 分钟。
- 抽查的小时合计对不上 12 个 5 分钟桶。
- coarse 物化连续失败。
- 分区删除前的 `expired` 不是真。
