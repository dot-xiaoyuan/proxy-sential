# 高性能流式存储与投影方案

状态：设计提案；Phase 1 影子发布、Phase 2a 收据、Phase 2b ClickHouse 事实、Phase 2c PostgreSQL 事实和 Phase 2d 影子设备当前态均已上线 184（真实发现事件 → Redpanda → ClickHouse/PG 影子事实 → PG 影子当前态，消费者 lag 已归零；见 [事件总线 Phase 1](event-bus-phase1.md) 与 [Phase 2](event-bus-phase2-shadow-receipts.md)）。最终 device_current、Redis、changes、比对和读取切换仍未开始，未做容量验收。本文用于替换“PostgreSQL 控制面 + ClickHouse 事件存储、禁止引入消息队列”的旧边界；旧约束已在 `AGENTS.md` 调整为“按性能目标选型”，同时保留安全、审计和不可放宽的边界。

## 1. 目标与判断

### 1.1 为什么现在要改

只读分析（[存储积压只读分析](storage-backlog-readonly-analysis-20261030.md)）确认，三个积压不是单点代码 bug：

- NCU 会话当前态写在约 203 万行、5 GB、11 个索引的 `account_sessions` 上，单批 10 条会话要 0.7—5.1 秒。
- 识别覆盖每分钟对 1,126 万行/16 GB 的收据分区重算 24 小时窗口。
- 发现投影每段 933—993 条事件要在 PostgreSQL 写事件键、收据、事实、变化，再做 933 次随机主键探测；整段一个事务，8 秒超时全部回滚，同一段无限重试，最后把捕获队列拖满并退出进程。

旧的“只用 PostgreSQL + ClickHouse，新增消息队列必须先证明必要性”约束，确实把设计推向“在 OLTP 表里模拟队列和每事件账本”。放开选型后，正确的方向不是“把同样的写入搬到 Kafka”，而是：

1. **用流式总线解耦采集、投影、归档和统计**，让慢消费者不再阻塞采集。
2. **把每事件账本从 PostgreSQL 移到 ClickHouse**，PostgreSQL 只保留权威当前态、控制面和小型回执。
3. **把热状态从大表移到小表 + Redis**，会话/设备当前态只保留开放或活跃部分。
4. **把窗口统计改成摄入时/分钟级增量聚合**，查询只合并小结果。
5. **用分区键、批量、幂等和检查点实现有界恢复**，不再整段重来、无限重试。

消息队列解决的是“解耦、缓冲、重放、按 key 排序、削峰”，不能自动解决“每事件写放大、全窗口重算、无界重试”。这四件事仍必须在数据模型和消费逻辑里修掉。

### 1.2 目标

| 维度 | 目标（单套 184 级别环境） | 说明 |
| --- | --- | --- |
| 持续吞吐 | 184 单机 100 条/秒级；新增 SSD 节点后 500 条/秒；生产 3 节点 5,000 条/秒短时峰值 | 当前约 4 条/秒；先按 25—125 倍余量设计 |
| 当前态可见 | Kafka 到 PostgreSQL/Redis 当前态 P95 ≤ 500 ms、P99 ≤ 1 s | 不包含上游采集和网络 |
| 事件可查 | Kafka 到 ClickHouse 可查 P99 ≤ 2 s | 批量异步插入 |
| 统计新鲜度 | `as_of` ≤ 1 分钟，24 小时查询 P95 ≤ 500 ms | 分钟级聚合，不再扫原始收据 |
| 采集可靠性 | 消费者变慢不导致采集进程退出；缺口可见 | 捕获只依赖本地 spool + Kafka |
| 恢复 | 消费崩溃/重启后从 offset 重放，重复写幂等 | 至少一次 + 幂等落点 |
| 保留 | 热查 30 天，归档 1 年 | ClickHouse TTL + 对象存储 |
| 运维 | 单节点可跑；生产可横向扩 broker/consumer/CH | 不要求一步到位 |

### 1.3 非目标

- 不改风险评分、证据语义、策略“仅记录”语义和前端展示规则。
- 不实际发送通知、下线、封禁或解封；不生成 AI 通报。
- 不做历史全量回填；旧历史仍按不可变起点和审计边界处理。
- 不承诺端到端 exactly-once；采用至少一次 + 幂等写 + 可重放，边界写清楚。
- 不在本文宣称容量已达标；所有数字都是设计假设，需用回放和现场受限输入验证。

## 2. 设计原则

1. **事件日志是主干**：采集先写 Kafka/Redpanda，消费者按自己的节奏读；任何下游变慢只产生 lag，不阻塞采集。
2. **CQRS 和读写分离**：写模型是流处理器 + 热状态；读模型是 PostgreSQL 当前态、ClickHouse 历史/统计、Redis 缓存。
3. **一份权威原文**：原始事件正文在 ClickHouse/对象存储；PostgreSQL 不保存每事件全文，只保存当前态、控制面、审计和小型 offset/outbox。
4. **按业务键分区**：同一会话、同一设备、同一账号的事件进同一分区，保证单 key 顺序；不承诺跨 key 全局顺序。
5. **至少一次 + 幂等落点**：offset 在 sink 确认后提交；重复消息靠版本号、事件键、内容哈希和 `ReplacingMergeTree` 抵消。
6. **有界工作**：每批按事件数和字节数限额；重试有上限、退避和抖动；失败进 DLQ；没有“无限重试同一段”。
7. **热/冷分层**：Kafka/Redis/PG WAL 放 NVMe；ClickHouse 热分区放 NVMe 或本地 SSD，冷分区下沉 HDD/对象存储。
8. **预聚合**：统计在写入路径或分钟级任务中增量维护，查询只读小结果。
9. **影子迁移**：先双写/影子比较，再切读，再退役旧路径；每阶段可回退。

## 3. 目标架构

```text
采集器 / 旧 4K 桥 / 被动发现 / Zeek
        │  标准事件（JSON/Protobuf）
        ▼
   producer（本地 spool + 幂等 + acks=all）
        │
        ▼
┌──────────────────────────── Redpanda / Kafka ────────────────────────────┐
│ ps.events.raw.v1      ps.discovery.events.v1     ps.identity.events.v1    │
│ ps.recognition.results.v1     ps.control.outbox.v1     ps.dlq.*.v1        │
└───────────────┬──────────────────────┬──────────────────────┬────────────┘
                │                      │                      │
        archiver（批量）       discovery-projector     identity-deriver
                │                      │                      │
                ▼                      ▼                      ▼
     ClickHouse events_raw     Redis 热状态 + PG device_current   Redis 热状态 + PG session_open
     （30 天热，1 年归档）     ClickHouse receipts/changes        ClickHouse session_history
                │                      │                      │
                └──────────────┬───────┴──────────────┬───────┘
                               ▼                      ▼
                    recognition-aggregator      API / control-plane
                    ClickHouse minute/hourly     Redis/PG 当前态 + CH 历史/统计
```

`archiver` 也可以直接消费域主题（事件信封内联正文或带 `body_ref`）；`ps.events.raw.v1` 只用于没有标准事件的原始段，避免默认双写。

### 3.1 组件职责

| 组件 | 职责 | 不负责 |
| --- | --- | --- |
| Redpanda / Kafka | 事件传输、缓冲、按 key 分区、重放、削峰 | 不承担最终查询和权威当前态 |
| producer | 标准化事件、写 Kafka、本地 spool、幂等 | 不做业务投影 |
| archiver | 批量写 ClickHouse 原文、对象存储归档 | 不写 PostgreSQL 每事件账本 |
| discovery-projector | 按设备合并事实、写当前态、写收据/变化 | 不做全量历史重建 |
| identity-deriver | 按会话合并、写开放会话/端点当前态、写历史 | 不更新整张设备画像 |
| recognition-aggregator | 分钟级识别统计、覆盖聚合 | 不扫 24 小时原始收据 |
| PostgreSQL | 控制面、策略/案件/审计、权威当前态、outbox、offset | 不存每事件收据/变化正文 |
| ClickHouse | 原始事件、收据、变化、历史、统计聚合 | 不做高频点更新 |
| Redis | 热状态、读缓存、去重/限流辅助 | 不作为唯一权威存储 |
| 对象存储 | 1 年归档、Parquet/压缩原文 | 不参与在线点查 |

## 4. 主题与事件契约

### 4.1 主题

| 主题 | key | 分区 | 保留 | 清理 | 生产者 → 消费者 |
| --- | --- | --- | --- | --- | --- |
| `ps.events.raw.v1` | `sensor_id:source:file_id` | 12 | 7 天 | delete | 仅原始段来源 → archiver |
| `ps.discovery.events.v1` | `device_key` | 24 | 7 天 | delete | 发现解析 → archiver、discovery-projector、recognition |
| `ps.identity.events.v1` | `session_id` | 24 | 7 天 | delete | 身份桥/解析 → archiver、identity-deriver |
| `ps.recognition.results.v1` | `device_key` 或 `event_key` | 12 | 7 天 | delete | recognition-worker → aggregator |
| `ps.control.outbox.v1` | `outbox_id` | 6 | 30 天 | delete | PG outbox relay → 控制面消费者 |
| `ps.dlq.<stage>.v1` | 原 key | 3 | 14 天 | delete | 各消费者失败记录 |

每个来源只写一个域主题，archiver 与 projector 同源消费；只有没有标准事件的原始段才单独写 `ps.events.raw.v1`。不要把“raw + 域主题”默认双写；确需双主题时用 Kafka 事务或 outbox 保证一致。

没有业务 key 的事件不能随机分区：身份事件优先 `session_id`，其次 `account_id + started_at`；发现事件优先 `device_key`，其次 `scope_id + 规范化 MAC/IP`；仍然没有稳定 key 的事件进 DLQ，不静默丢弃。

分区数按“消费者并行度 = 分区数”设计；单 key 顺序由分区保证。热点设备/账号可能造成分区倾斜，需要监控每分区 lag 和字节速率；必要时为超大 key 单独建主题或加哈希前缀拆分区，并由消费端合并，但不能破坏同 key 的处理顺序。对需要跨事件类型保序的设备事实，不要按 event_type 拆主题。

### 4.2 事件信封

```json
{
  "schema_version": 1,
  "event_id": "sensor:epoch:event",
  "event_type": "discovery",
  "sensor_id": "ncu-184-router-pilot",
  "scope_id": "bond0-passive-pilot",
  "partition_key": "device:...",
  "observed_at": "2026-10-30T02:15:00.123Z",
  "accepted_at": "2026-10-30T02:15:00.456Z",
  "content_hash": "sha256:...",
  "body_ref": "ch://events_raw/20261030/...",
  "payload": {}
}
```

- `event_id` 是稳定业务键，重放不重新生成。
- `content_hash` 用于同键不同内容冲突检测；冲突不能静默覆盖。
- `body_ref` 指向 ClickHouse 原文；小事件可直接内联，大事件只放引用。
- Schema 用 Protobuf/Avro + 版本号（配 Redpanda Schema Registry、Buf 或仓库内 `.proto` 版本管理）；第一阶段可用带 `schema_version` 的 JSON，后续再换二进制编码。主题名带 `.v1`，不兼容变更升 `.v2`。

## 5. 三条链路的处理设计

### 5.1 发现投影

**输入**：`ps.discovery.events.v1`，按 `device_key` 分区。

**热状态**：Redis hash `disc:{epoch}:{device_key}`，保存压缩后的设备事实集合：

```json
{
  "version": 1842,
  "last_seen": "2026-10-30T02:15:00Z",
  "facts": {
    "dhcp:...": {"event":"...","revision":3,"observed":"...","valid_until":"...","semantic_hash":"...","fields":{}}
  }
}
```

**处理**：

1. 一次 poll 批次先按 `device_key` 分组；同一设备的多条事件在内存中合并，只做一次 Redis 读写和一次 PG upsert。读 Redis 当前态（miss 时从 ClickHouse `discovery_facts_current` 或 PostgreSQL 重建）。
2. 对每条事件按 `(observed_at, revision, event_id)` 与已存版本比较；旧事件记 `late_history`，重复事件只更新 `last_seen`/计数，不写新事实；收据仍按事件键幂等写入。
3. 撤销/更正/恢复按现有语义处理；冲突保留证据并告警。
4. 批量写 ClickHouse：`discovery_receipts`（每事件）、`discovery_changes`（可见变化）、`discovery_facts_current`（当前事实）。
5. 批量 upsert PostgreSQL `device_current`（每 200—500 ms 或每 500—2,000 个设备），只写 dirty 设备。
6. 写 Redis 新状态（Lua 原子版本比较），把版本推进到已写 sink 的状态。
7. 三个 sink 都确认后提交 Kafka offset；任一失败则重放，重复靠版本/事件键幂等。

**崩溃窗口**：Redis 更新必须放在 sink 之后、offset 之前；不能把“Redis 已有版本”当成“已提交”。如果崩溃发生在 CH/PG 写成功但 offset 未提交，重放会再写一次（幂等），然后推进 Redis；如果先更新 Redis 再写 sink，崩溃会让重放误以为事件已处理而漏写 sink。

**为什么快**：

- 没有每事件 PostgreSQL 主键探测；事实合并发生在 Redis/内存。
- PostgreSQL 只写“变化的设备”，每批一条多行 upsert，索引 2—3 个。
- ClickHouse 批量插入，单批 1,000—10,000 行；用 `ReplacingMergeTree` 去重。
- projection 变慢只增加 Kafka lag，不阻塞采集。

**目标**：Kafka → PostgreSQL 当前态 P99 ≤ 500 ms；Kafka → ClickHouse 可查 P99 ≤ 2 s。

### 5.2 NCU 身份派生与归档

**输入**：`ps.identity.events.v1`，按 `session_id` 分区；归档走 `ps.events.raw.v1`。

**热状态**：Redis hash `sess:{session_id}`，字段包括账号、端点、IP/MAC、started_at、last_confirmed_at、status、version；关闭会话后保留短 TTL 供查询。

**处理**：

1. 一次 poll 批次先按 `session_id` 分组；同一会话的多条事件在内存中合并，只做一次 Redis 读写和一次 PG upsert。按 `session_id` 顺序消费；同时间戳下线优先，早到时间保留区间，旧事件不覆盖新状态。
2. 每 200 ms 或 500 条批量 upsert PostgreSQL `session_open`（只含开放会话，3 个索引）和 `endpoint_current`（2 个索引）。
3. 关闭会话写入 ClickHouse `identity_session_history`，并从 `session_open` 删除或标记 closed；历史查询走 ClickHouse。
4. 归档消费者从 `ps.identity.events.v1`（或 raw 主题）批量写 ClickHouse `events_raw`，不再每片段 4 个 PostgreSQL 事务 + 2 次 ClickHouse 请求。
5. 写 Redis 新状态；同一会话的版本单调推进；会话关闭后旧事件不能重新打开，必须用 version/status 复核。
6. sink 确认后提交 offset；重复/晚到/撤销按版本和事件键幂等。

**为什么快**：

- `session_open` 只保留开放会话（现场约千级，而不是 203 万行全量），热表小、索引少。
- 历史会话移出 PostgreSQL，写入是追加而不是更新大表。
- 归档是纯批量追加，不再逐片段领取/确认。

**目标**：会话当前态 P99 ≤ 500 ms；归档 lag P95 ≤ 5 s；不再出现“计数器永远不归零”的混合积压。

### 5.3 识别覆盖统计

**输入**：`ps.recognition.results.v1` 或直接从 `ps.discovery.events.v1` 派生。

**处理**：

1. 每条识别结果写 ClickHouse `recognition_raw`（`ReplacingMergeTree(version)`，按 `event_key` 去重）。
2. 每分钟调度一次有界聚合：`INSERT INTO recognition_minute SELECT ... FROM recognition_raw FINAL WHERE minute = ...`，写 `AggregatingMergeTree` 的 `countState`、`avgState`、`quantilesState`。
3. 每小时/每天从分钟表继续合并，得到 `coverage_hourly`/`coverage_daily`。
4. API 只读 `recognition_minute` 最近 1,440 行（24 小时）或小时表，带 `as_of`、窗口和版本；不再扫原始收据，不再用 `percentile_cont` 对 1,126 万行排序。

**为什么不用物化视图直接聚合**：至少一次重放会让普通 MV 重复计数；`ReplacingMergeTree` 原始表 + 调度聚合可以先去重再计数，代价是分钟级延迟（可接受）。如果采用 Kafka 事务或 ClickHouse 去重令牌，也可以改成 MV，但必须先证明重复不重复计数。

**目标**：`as_of` ≤ 1 分钟；24 小时查询 P95 ≤ 500 ms；统计任务失败不阻塞实时链路。

## 6. 存储设计

### 6.1 PostgreSQL

只保留控制面、权威当前态、审计和小型账本：

| 表 | 主键 | 关键列 | 索引 | 说明 |
| --- | --- | --- | --- | --- |
| `device_current` | `device_key` | scope_id、last_seen、classification、name、model、version、document | `(scope_id,last_seen DESC)`、`(classification,last_seen DESC)` | 设备列表/详情当前态；document 只放展示字段 |
| `session_open` | `session_id` | account_id、endpoint_id、ip、mac、started_at、last_confirmed_at、status、version | `(account_id)`、`(endpoint_id)`、`(last_confirmed_at) WHERE status='open'` | 只含开放会话 |
| `endpoint_current` | `endpoint_id` | primary_mac、role、last_seen、version | `(primary_mac)` | 端点当前态 |
| `outbox` | `id` | topic、key、payload、created_at、published_at | `(published_at) WHERE published_at IS NULL` | PG 事务性发件箱 |
| `ingest_offset` | `(source,partition)` | offset、updated_at | 主键 | 非 Kafka 来源的位点 |
| 控制面表 | 不变 | users/policies/cases/audit | 现有 | 不在本文改造 |

原则：

- 不在 PostgreSQL 保存每事件收据、事件键、变化正文；这些进 ClickHouse。
- 当前态表不做全量历史更新；只 upsert 变化的 key。
- 版本号单调递增（`observed_at` + `revision` + `event_id` 作为 tie-break），`ON CONFLICT ... WHERE EXCLUDED.version > current.version`；同版本不同内容进入冲突记录，不静默覆盖。
- 批大小 500—2,000 行/事务；避免长事务和跨批锁。

### 6.2 ClickHouse

| 表 | 引擎 | 分区/排序 | TTL | 用途 |
| --- | --- | --- | --- | --- |
| `events_raw` | `ReplacingMergeTree(ingest_version)` | `PARTITION BY toYYYYMMDD(accepted_at)`，`ORDER BY (sensor_id,event_type,event_id,content_hash)`；按设备查询走 projection | 30 天转冷，1 年删除 | 唯一原文/证据；同键不同哈希保留冲突 |
| `discovery_receipts` | `ReplacingMergeTree(version)` | `PARTITION BY toYYYYMM(accepted_at)`，`ORDER BY (epoch,scope_id,event_key,content_hash)` | 30 天/1 年 | 每事件回执与去重；同键不同哈希保留冲突 |
| `discovery_changes` | `ReplacingMergeTree(version)` | `PARTITION BY toYYYYMMDD(accepted_at)`，`ORDER BY (epoch,device_key,event_key,change_kind)` | 30 天 | 可见变化历史 |
| `discovery_facts_current` | `ReplacingMergeTree(version)` | `ORDER BY (epoch,device_key,fact_key)` | 当前态 | 事实当前值 |
| `identity_session_history` | `ReplacingMergeTree(version)` | `PARTITION BY toYYYYMM(started_at)`，`ORDER BY (session_id,started_at)` | 1 年 | 已结束会话历史 |
| `recognition_raw` | `ReplacingMergeTree(version)` | `PARTITION BY toYYYYMMDD(accepted_at)`，`ORDER BY (sensor_id,event_key,content_hash)` | 30 天 | 识别原始结果/去重；冲突保留 |
| `recognition_minute` | `AggregatingMergeTree` | `PARTITION BY toYYYYMMDD(minute)`，`ORDER BY (minute,protocol)` | 1 年 | 分钟统计状态 |
| `coverage_hourly` | `AggregatingMergeTree` | `ORDER BY (hour,protocol)` | 1 年 | 小时/24 小时统计 |
| `coverage_daily` | `AggregatingMergeTree` | `ORDER BY (day,protocol)` | 1 年 | 日统计/长期趋势 |

要点：

- `events_raw` 的 `ORDER BY` 以 `(sensor_id,event_type,event_id,content_hash)` 做去重键；同键不同哈希保留两行，不静默覆盖；设备/时间查询另建 projection，避免为了查询顺序破坏去重键。
- `ReplacingMergeTree` 的去重发生在后台合并，查询当前值需要 `FINAL`/`argMax`，或直接读 PostgreSQL/Redis；不要对大范围历史查询使用 `FINAL`。
- 用 `LowCardinality` 存协议、类型、来源等低基数字段；`ZSTD` 压缩大字段。
- 写入用批量 `INSERT` + `async_insert=1, wait_for_async_insert=1`（确认已落盘再提交 offset）或每批 1—10 MB；每批带 `insert_deduplication_token`，重试不重复。
- 点查当前值用 `FINAL` 或 `argMax`，只限小范围；大范围历史查询避免 `FINAL`。
- 分区按天/月，提前创建未来分区；保留任务按 TTL 或 `DROP PARTITION`，不再出现“写到 default 分区”。
- 1 年归档用 ClickHouse 分层存储（S3/MinIO）或 Parquet 导出 + 清单/哈希；在线只查 30 天。

### 6.3 Redis

| key | 类型 | TTL | 用途 | 丢失后果 |
| --- | --- | --- | --- | --- |
| `disc:{epoch}:{device_key}` | hash/string | 24h | 设备事实热状态 | 从 CH/PG 重建，短暂延迟 |
| `sess:{session_id}` | hash | 24h | 会话热状态 | 从 PG/CH 重建 |
| `api:cache:*` | string | 5—30s | 读缓存 | 回源 PG/CH |
| `lock:*` | string | 短 | 去重/限流 | 可重试 |

Redis 不作为唯一权威：AOF `everysec` + 副本；Redis 丢数据时从 PostgreSQL/ClickHouse 重建。禁止把 Redis 当长期事件存储。

### 6.4 对象存储

- 1 年归档：Parquet/压缩原文 + manifest（分区、行数、哈希、覆盖范围）；对象存储用独立节点或现有 S3/MinIO，不与 ClickHouse 热盘共用同一块机械盘。
- 保留策略：热 30 天在 ClickHouse；冷 1 年在对象存储；案件引用独立保护，不随 TTL 删除。
- 归档任务与在线查询隔离，限速、可中断、记录缺口。

## 7. 一致性与故障恢复

### 7.1 语义

- **端到端至少一次**：Kafka 重放、消费者重启、网络超时都可能重复。
- **当前态幂等**：PostgreSQL 用单调版本；ClickHouse 用 `ReplacingMergeTree`；Redis 用版本比较 Lua。
- **聚合幂等**：先写 `ReplacingMergeTree` 原始结果，再按分钟去重聚合；避免 MV 在重放时重复计数。
- **offset 提交**：所有 sink 确认后提交；sink 失败不提交，重放。
- **DLQ**：毒消息/内容冲突最多 3 次（可配置），之后写 `ps.dlq.<stage>.v1`，保留原 key、错误、时间、内容哈希；基础设施错误（CH/PG/Redis 不可用）先暂停分区，不消耗记录重试次数。修复工具可重放 DLQ。

### 7.2 故障矩阵

| 故障 | 行为 | 恢复 |
| --- | --- | --- |
| 采集器/生产者与 Kafka 断开 | 本地 spool 继续写；spool 满则暂停采集并记录缺口 | 网络恢复后按序重发；缺口可查 |
| 消费者崩溃 | offset 未提交，重启重放 | 幂等写抵消重复 |
| ClickHouse 慢/不可用 | 消费者暂停该分区，lag 增长；不回滚已写 PG | CH 恢复后批量重试；DLQ 兜底 |
| PostgreSQL 慢/不可用 | 当前态批次暂停；CH 继续写 | PG 恢复后重放；当前态短暂落后 |
| Redis 丢失 | 从 PG/CH 重建热状态 | 重建期间读回源 |
| Broker 磁盘满 | 生产被拒绝；spool 满后暂停采集并告警 | 扩容/清理；按 offset 重放 |
| 毒消息/内容冲突 | 重试 3 次后进 DLQ，不阻塞后续 key | 人工修复/重放 |
| 分区倾斜 | 单分区 lag 高 | 增加分区/拆主题/优化 key |

### 7.3 Exactly-once 边界

不承诺端到端 exactly-once。需要 exactly-once 的位置只有“当前态不被旧事件覆盖”和“聚合不重复计数”，这两者用版本比较 + 去重表实现。Kafka 事务可以作为后续优化，但不是第一阶段的前提。

## 8. 过载与背压

- 生产者：`acks=all`、`enable.idempotence=true`、压缩 `zstd`、`linger.ms=5—20`、批量 64—256 KB；本地 spool 1—2 GB。
- 消费者：有界队列；一次 poll 内按业务 key 分组，同 key 合并后只读写一次热状态；sink P99 超过阈值时 `Pause` 分区，恢复后 `Resume`；消费者数不超过分区数。
- 捕获：捕获只依赖本地 spool + Kafka，不直接依赖投影/CH；下游慢不杀采集进程。spool 满时暂停并记录缺口，不静默丢弃。
- 重试：指数退避 + 抖动，单记录最多 3 次；连续失败触发熔断/暂停，避免重试风暴。
- 负载分级：实时投影优先，归档/统计/回填独立消费组和配额；Kafka 分区级别限流。

## 9. 容量与资源

### 9.1 基线

- 当前输入约 4 条/秒、约 35 万条/天；PostgreSQL 158 GB，ClickHouse 与 PG 共用一块 1.8 TB 机械盘。
- 当前峰值未知；设计按 100/500/1,000 条/秒三档估算，实际以现场测量为准。

### 9.2 容量估算

假设平均事件 1 KB、ClickHouse 压缩 5 倍、Kafka 3 副本、7 天保留；实际应按现场样本修正事件大小：

| 速率 | 原始/天 | CH 压缩/天 | CH 30 天 | Kafka 7 天×3 副本 | 单机可行性 |
| --- | ---: | ---: | ---: | ---: | --- |
| 100/s | 8.6 GB | 1.7 GB | 52 GB | 181 GB | 单机可行 |
| 500/s | 43 GB | 8.6 GB | 259 GB | 907 GB | 需要 NVMe + 对象存储/分层 |
| 1,000/s | 86 GB | 17 GB | 518 GB | 1.8 TB | 单机 HDD 不可行；需多节点/分层 |

184 当前只有 1.8 TB 机械盘、约 203 GB 可用；**不能**在单机 HDD 上同时承载 1,000/s × 7 天 × 3 副本 + 30 天 CH。建议：

- 184 单机目标：100 条/秒级；新增一台 SSD 节点（Redpanda/Redis/消费者）后 500 条/秒持续、1,000 条/秒短时峰值。
- 生产目标：3 个 Redpanda broker（或 3 节点 Kafka）、ClickHouse 2 副本/分片、PostgreSQL 主备；1,000/s 以上按节点水平扩展。
- Kafka 保留 3—7 天，冷数据尽快下沉对象存储；不要用 Kafka 当长期归档。

### 9.3 部署拓扑与资源建议

184 当前已经给 PostgreSQL 32 GiB、ClickHouse 24 GiB，合计约 56 GiB，宿主机只有约 62 GiB；**再在 184 上叠加 Redpanda 和 Redis 会把内存和磁盘 I/O 挤爆**。因此推荐两节点拓扑，而不是把所有组件塞进 184。

**推荐：184 保留 PG/CH，新增一台 SSD 节点承载总线、热状态和消费者。**

| 节点 | 组件 | CPU | 内存 | 磁盘 |
| --- | --- | ---: | ---: | --- |
| 新 SSD 节点 | Redpanda（测试单节点，生产 3 节点） | 4 | 8 GB | 200 GB NVMe |
| 新 SSD 节点 | Redis | 2 | 4 GB | 50 GB NVMe |
| 新 SSD 节点 | Go 消费者 | 4 | 6 GB | — |
| 新 SSD 节点 | 合计 | 10 | 18 GB | 250 GB NVMe |
| 184 | PostgreSQL | 4 | 16—32 GB | 300 GB |
| 184 | ClickHouse | 8 | 24 GB | 1 TB HDD + 200 GB NVMe 缓存 |

**单机 184 备选**：只适合 100 条/秒级。需要把 PG/CH 降到约 16/16 GiB，给 Redpanda/Redis/消费者留出 10—14 GiB，并接受现有查询变慢；上线前必须先做内存、IOPS 和 CH merge 实测。不要把 9.3 的组件配额直接相加后声称 184 能跑 500/s。

如果无法加 NVMe，Redpanda 的发布延迟和 Redis AOF 会受机械盘影响；此时应把目标降到 100 条/秒级，或把 Kafka/Redis 放到独立 SSD 节点。容量承诺必须附实测，不能用本表直接宣称达标。

## 10. 查询与读模型

- 当前设备列表/详情：Redis 缓存 → PostgreSQL `device_current`；如果 Redis 版本落后于 PG 当前版本，直接读 PG 并回填缓存；游标分页，索引 `(scope_id,last_seen DESC)`。
- 当前会话/端点：Redis → PostgreSQL `session_open`/`endpoint_current`。
- 历史事件/证据：ClickHouse `events_raw`/`discovery_changes`/`identity_session_history`，按设备/时间范围分页；不加载全量后分页。
- 统计：ClickHouse `recognition_minute`/`coverage_hourly`，按协议聚合后 24 小时最多 1,440 个时间点；附 `as_of`、窗口、版本。
- 缓存：按结果版本失效；失败/无记录/处理中/过期明确区分；不跨 key 持锁慢加载。

## 11. 迁移与切换

| 阶段 | 工作 | 读路径 | 回退 | 验收 |
| --- | --- | --- | --- | --- |
| 0 基线 | 记录输入速率、P95/P99、PG/CH 大小、IOPS、lag | 不变 | — | 基线报告 |
| 1 总线影子 | 部署 Redpanda；发现原始事件双写 Kafka；不切读 | 旧路径 | 关闭双写 | 双写计数/哈希一致，lag 可观测 |
| 2 发现投影 | 新 projector 写 CH + PG `device_current` 影子表；单传感器 canary | 影子比较 | 切回旧 projector | 24 小时无缺口，当前态一致 |
| 3 归档 | `ps.events.raw.v1`（或域主题）→ CH 批量归档；NCU 旧片段保留回退 | 归档读新表 | 旧导出 | 原文/哈希/引用可查；17 个旧缺口修复 |
| 4 身份会话 | 建 `session_open`；双写；切 Kafka 消费者 | 会话读新表 | 旧 `account_sessions` | 开放会话延迟、乱序/关闭语义 |
| 5 统计 | CH `recognition_minute` 回填 24 小时；切 API | 统计读 CH | 旧 24h 扫描 | `as_of` ≤1 分钟，查询 P95 |
| 6 退役 | 停旧表写入/索引；保留只读视图；清理 | 新路径 | 视图回退 | 30 天影子无回退需求 |

迁移原则：

- 先影子/双写，再切读，再退役；每阶段独立开关和回退。
- 不回写历史，不移动固定起点；旧历史缺口按审计边界保留。
- 不在 184 造数压测；用真实输入和受限 canary 观察。
- 数据库迁移只新增，不改写已应用迁移；保留旧表和视图至少一个观察周期。

## 12. 验证与验收

### 12.1 功能

- 重复、乱序、晚到、更正、撤销、自然过期、内容冲突。
- 会话关闭/重开、同时间戳下线优先、A→B→C→B 迁移。
- 设备事实撤销/恢复、跨来源冲突、案件引用保护。
- 消费者崩溃、broker 重启、CH/PG/Redis 短时不可用、磁盘满、网络分区。
- DLQ 重放、offset 重放、幂等写不产生重复计数。

### 12.2 性能

| 指标 | 目标 | 方法 |
| --- | --- | --- |
| 持续吞吐 | 500/s（184 测试 100—200/s） | 真实回放 + 受限 canary |
| Kafka lag | P95 ≤ 1 s | 每分区监控 |
| 当前态 | P95 ≤ 500 ms、P99 ≤ 1 s | 端到端时间戳 |
| CH 可查 P99 | ≤ 2 s | 写入到查询 |
| 统计 `as_of` | ≤ 1 分钟 | 聚合任务时间 |
| API | P95 ≤ 500 ms、P99 ≤ 1 s | 现有门槛 |
| 采集缺口 | 0（可解释的暂停除外） | 捕获统计/日志 |
| DLQ | 可解释、可重放 | 每 stage 计数 |

### 12.3 容量

- 24 小时持续输入 + 峰值；记录 CPU、内存、磁盘、IOPS、网络、CH merge、PG 锁、Redis 命中率。
- 30 天热数据 + 1 年归档的磁盘增长；分区/TTL 生效。
- 故障注入后的恢复时间、重复量、缺口。
- 结论必须附硬件、数据分布、负载和观察窗口；短样本不外推。

## 13. 风险与备选

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| 新组件运维复杂度 | 故障面增加 | 选 Redpanda 降低 JVM/ZK 负担；单节点测试、生产 3 节点；runbook |
| 单机 HDD | Kafka/Redis 延迟高 | NVMe；否则降到 100/s 级或独立节点 |
| 双写不一致 | 影子比较失败 | 以 Kafka 为主、PG/CH 为派生；outbox；对账 |
| Schema 演进 | 消费者不兼容 | `.v1` 主题 + 版本号；Protobuf/Avro；兼容性测试 |
| 重复计数 | 统计偏差 | `ReplacingMergeTree` + 调度聚合；幂等版本 |
| Redis 丢失 | 当前态短暂缺失 | 从 PG/CH 重建；不作为唯一权威 |
| 单机单点 | 一台机器故障影响全链路 | 生产拆 3 broker/CH 副本/PG 主备；单机只用于测试 |
| 安全 | 未授权访问 | SASL/TLS、网络隔离、密钥管理 |
| 过度设计 | 当前 4/s 用不上 500/s | 分阶段；先解决发现投影和统计，再扩总线 |

### 备选方案

1. **继续 PostgreSQL + ClickHouse，只做批量和分区**：运维最简单，能缓解部分问题；但按当前写放大和机械盘模型估算，难以稳定支撑 100/s 以上，需实测。适合作为阶段 0/回退。
2. **Kafka + Flink**：事件时间窗口、状态、checkpoint 更强；但 JVM/Flink 运维重，当前 Go 团队和单机环境不划算。只有出现复杂 CEP/窗口需求再引入。
3. **NATS JetStream**：更轻，Go 友好；但 ClickHouse 生态和工具链不如 Kafka，适合较小规模。若团队不想运维 Kafka，可作为备选。
4. **Redis Streams**：实现简单，但内存/保留/副本模型的耐久性不适合作为系统事件主干；只建议做热缓存/轻量队列。
5. **Pulsar**：分层存储、多租户强；运维更重，当前规模不需要。

**推荐**：Redpanda（Kafka API）+ Go 消费者 + Redis + PostgreSQL 当前态 + ClickHouse 事件/统计 + 对象存储归档。保留 Kafka 作为等价实现选项，避免绑定单一厂商。

## 14. 下一步

1. 在 184 加 NVMe（或独立 SSD 节点），先做 Redpanda 单节点 + 1 个主题的影子双写；验证生产/消费延迟、磁盘和 spool。
2. 用真实发现事件做 24 小时影子投影：新 projector 写 CH + PG 影子表，与旧路径比对设备状态、收据、变化。
3. 通过后先切发现投影（收益最大、风险最集中），再切归档，再切身份会话，最后切统计。
4. 每个阶段保留旧路径和回退开关；不一次性全量切换。
5. 所有容量结论附硬件、数据分布、负载和观察窗口；不以本地 mock 或短样本替代现场验收。

### Phase 1 落盘状态

Phase 1 已实现发现事件的 Kafka 影子发布：`internal/eventbus`、发现分区键、`CapturedSegment` 回调、`discovery-worker` 接线、`cmd/event-bus-probe`、本地 Redpanda compose/脚本和测试。默认关闭，不改读取路径，不写业务表。2026-10-30 在 184 用主机二进制 + systemd 单节点 Redpanda 完成部署验证（cluster healthy、主题创建、probe produce/consume、重启恢复）；Docker 18.09 的创建路径在本机卡住，旧 compose 单元已移除。运行方式、环境变量、184 命令和回退见 [事件总线 Phase 1](event-bus-phase1.md)。本阶段不代表投影、Redis、ClickHouse 账本或读取切换已完成。

## 15. 参考

- [Apache Kafka 文档](https://kafka.apache.org/documentation/)
- [Redpanda 文档](https://docs.redpanda.com/)
- [ClickHouse Kafka 引擎](https://clickhouse.com/docs/en/engines/table-engines/integrations/kafka)
- [ClickHouse ReplacingMergeTree](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/replacingmergetree)
- [ClickHouse AggregatingMergeTree](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/aggregatingmergetree)
- [Redis 持久化](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)
- [Transactional Outbox](https://microservices.io/patterns/data/transactional-outbox.html)
- [Google SRE: Handling Overload](https://sre.google/sre-book/handling-overload/)
- [Google SRE: Addressing Cascading Failures](https://sre.google/sre-book/addressing-cascading-failures/)
- [Apache Flink: Stateful Stream Processing](https://nightlies.apache.org/flink/flink-docs-stable/docs/concepts/stateful-stream-processing/)
- [存储积压只读分析](storage-backlog-readonly-analysis-20261030.md)
- [设备中心存储与查询设计](device-center-storage-query-design.md)
- [存储效率与重复历史审查](storage-efficiency-audit-20261024.md)
