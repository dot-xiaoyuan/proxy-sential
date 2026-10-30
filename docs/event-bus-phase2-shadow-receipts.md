# 事件总线 Phase 2：影子收据消费者

状态：Phase 2a 收据、Phase 2b ClickHouse 影子事实、Phase 2c PostgreSQL 影子事实、Phase 2d PostgreSQL 影子设备当前态均已在 184 上线；不改读取路径，不写最终 `device_current`，不写 Redis，不做新旧投影比对。总体方案见 [高性能流式存储与投影方案](high-performance-streaming-architecture-20261030.md)。

## 目标与边界

Phase 1 已证明真实发现事件能写入 Redpanda。本阶段只验证下一段：

```text
ps.discovery.events.v1
  -> Go consumer group（有界批次）
  -> ClickHouse eventbus_discovery_receipts（影子收据）
  -> ClickHouse eventbus_discovery_facts_shadow（影子事实，Phase 2b）
  -> PostgreSQL discovery_service_facts_shadow（影子事实，Phase 2c）
  -> PostgreSQL discovery_device_current_shadow（影子当前态，Phase 2d）
  -> Kafka offset commit
```

本阶段**不做**：

- `discovery_changes`、最终版 `discovery_facts_current`（当前只有 `eventbus_discovery_facts_shadow`，不是完整事实集合成）；
- PostgreSQL `device_current` 影子表；
- Redis 热状态和版本比较；
- 新旧投影结果比对；
- 读取切换、旧表退役；
- 生产多 broker、TLS/SASL、容量验收。

因此本阶段的“跑通”只代表 Kafka → 消费者 → ClickHouse 收据/影子事实链路可用，不代表完整新存储架构已上线。

## 实现

| 组件 | 位置 |
| --- | --- |
| Kafka 消费者、批次、offset 提交 | `internal/eventbus/projector.go` |
| ClickHouse HTTP 收据写入 | `internal/eventbus/clickhouse_receipts.go` |
| 消费者入口 | `cmd/event-bus-consumer/main.go` |
| ClickHouse 收据表迁移 | `migrations/clickhouse/057_eventbus_discovery_receipts.sql` |
| ClickHouse 影子事实表迁移 | `migrations/clickhouse/058_eventbus_discovery_facts_shadow.sql` |
| 事实派生（复用旧适配器） | `internal/eventbus/facts.go`、`internal/discovery/stream_facts.go` |
| ClickHouse 事实写入 | `internal/eventbus/clickhouse_facts.go` |
| PostgreSQL 事实写入 | `internal/eventbus/postgres_facts.go` |
| 设备当前态聚合 | `cmd/event-bus-current-shadow/main.go` |
| 多 sink 组合 | `internal/eventbus/multi_sink.go` |
| PostgreSQL 事实表迁移 | `migrations/postgres/202_discovery_facts_shadow.sql` |
| PostgreSQL 当前态表迁移 | `migrations/postgres/203_discovery_device_current_shadow.sql` |
| systemd 单元 | `deploy/systemd/proxy-sentinel-eventbus-consumer.service` |

消费语义：

- 当前 PG 事实阶段使用消费组 `ps-discovery-eventbus-facts-pg-v1`，从最早 offset 开始；`ps-discovery-eventbus-shadow-v1`、`ps-discovery-eventbus-facts-shadow-v1` 保留作历史；
- 一次最多 1,000 条或 500 ms 批次；
- 先写 ClickHouse 收据和事实，再写 PostgreSQL 事实，三者成功后提交该批 Kafka offset；
- 重复消费由 `eventbus_discovery_receipts` 的 `ReplacingMergeTree` 和 `event_id` 去重；
- 历史非法消息不会阻塞整个消费者：记录日志、跳过并随批次提交；生产中应改为 DLQ，这是本阶段明确的测试边界；
- 遇到 sink/commit 错误直接退出，由 systemd 重启并从已提交 offset 重放。

收据表使用 `ORDER BY (device_key, observed_at, event_id)`、`PARTITION BY toYYYYMM(observed_at)`、`TTL 30 天`，`envelope` 使用 ZSTD 压缩。该表是影子收据，不是新的权威原文表。事实表使用 `ORDER BY (device_key, fact_key)`、`ReplacingMergeTree(version)`，每个事实保留最新观测。

## 184 部署

- 发布目录：`/opt/proxy-sentinel/releases/2026.10.30-eventbus-p2`
- 消费者二进制 SHA256：`cbcc2d2bb6da167ee73c7d121f3fd6fac9b238c8acddbb9bafef7be8e67333e2`，源码提交 `14733541`
- 当前态聚合二进制 SHA256：`70404fdd99db0f5e95ca7b9ccec4ddeb463f9f8dcc9604698cb49d46e9020c9b`，源码提交 `7d8e474e`
- systemd：`proxy-sentinel-eventbus-consumer.service`，enabled + active
- 环境：复用 `/opt/proxy-sentinel/config/runtime.env` 中的 `PROXY_SENTINEL_CLICKHOUSE_DSN`，不在命令行和文档中展开凭据
- 表迁移：`057_eventbus_discovery_receipts.sql`、`058_eventbus_discovery_facts_shadow.sql`、`202_discovery_facts_shadow.sql` 已创建；账本 checksum 分别为 `0405391d8f77ad8e7cafeb30e765c4f4fed286795f4bbb96bf9dab75eab468b8`、`b31a1924207abbb66b13ed0b6bc452526afd1a9d94befcc47f34e473e60cc71d`、`6cd6109564ba9f321dcde4ba84366813b01eb6f6ed257827a8c6bf89b673d7b2`

启动/检查：

```bash
systemctl start proxy-sentinel-eventbus-consumer.service
systemctl status proxy-sentinel-eventbus-consumer.service
journalctl -u proxy-sentinel-eventbus-consumer.service -n 50 --no-pager
rpk -X brokers=127.0.0.1:19092 group describe ps-discovery-eventbus-shadow-v1
```

回退：

```bash
systemctl disable --now proxy-sentinel-eventbus-consumer.service
```

Kafka 中已有影子事件和 ClickHouse 表不会影响旧路径；如需清理，再单独删除表或保留作历史证据。

## 验证结果

2026-10-30 13:35:24 CST 的一致性快照：

| 指标 | 值 |
| --- | --- |
| 主题 6 分区 high-watermark 合计 | `24,626` |
| Phase 1 `published` | `24,623`，`failed=0`、`dropped=0`、`segments=28` |
| 消费组状态 | `Stable`，`TOTAL-LAG=0` |
| ClickHouse 收据行数 | `24,625` |
| `uniqExact(event_id)` | `24,625` |
| 计数关系 | `24,623 + 3 probe - 1 invalid skipped = 24,625` |

唯一被跳过的是早期验证遗留的 `smoke-1`（partition 3、offset 0，缺 `partition_key`）；日志有明确的 `skipping invalid record`。其余 3 条 probe 中有 2 条有效，已写入。

实际收据样本：

```text
event_id=stream-df971480e06a6e94a942aa67861e4e63
device_key=053ab71ab53fb224ca5bbdad78349c98
sensor_id=ncu-184-router-pilot
source=passive-discovery
kafka_partition=2
kafka_offset=3904
```

消费者重启后：

- 消费组保持 `Stable`，`TOTAL-LAG=0`；
- `uniqExact(event_id)` 与收据行数一致，未观察到逻辑重复；
- 新事件继续写入，`eventbus_discovery_receipts` 的行数和 `eventbus.stats.published` 同步增长。

## Phase 2b：影子事实表

2026-10-30 13:40 CST 在原有收据链路后追加了事实级影子写入：

- 新增表 `eventbus_discovery_facts_shadow`，迁移 `058_eventbus_discovery_facts_shadow.sql`；
- 每行是 `(device_key, fact_key)` 的最新观测，按 `version`（observed_at 纳秒）做 `ReplacingMergeTree`，晚到的旧事件不会覆盖新事实；
- 事实键复用现有发现投影的 `AdaptDiscoveryEvent`、`FromEvent`、`discoveryStateKey`、`discoveryFactKey`，新代码只做只读适配，不写旧表；
- 消费者同一批次先写收据，再写事实，两者都成功后才提交 Kafka offset；
- 非私有地址或非设备证据的 probe 只跳过事实、不阻断收据；生产仍应 DLQ。

2026-10-30 13:41 CST 核验：

| 指标 | 值 |
| --- | --- |
| 收据唯一事件数 | `35,662` |
| 消费组 | `ps-discovery-eventbus-facts-shadow-v1`，`Stable`，`TOTAL-LAG=0` |
| 事实表 `count() FINAL` | `774` |
| 唯一 `(device_key, fact_key)` | `774` |
| 涉及设备 | `458` |

事实表当前不是完整 `device_current`：它只保存每个事实的最新观测，不把多个事实合并成设备当前态，也没有写入 PostgreSQL。事实数远小于收据数，是因为同一设备/服务的重复公告被 `ReplacingMergeTree` 合并，不代表事件丢失。

发布：

- 二进制 SHA256：`c38ba1a7d8cc0d34b795c7194738b60359d6c840e0e79d06361b9e3b55f2b504`
- 源码提交：`a3ef42b3`
- 事实迁移账本 checksum：`b31a1924207abbb66b13ed0b6bc452526afd1a9d94befcc47f34e473e60cc71d`
- 服务仍是 `proxy-sentinel-eventbus-consumer.service`

重放边界：为了给已有事件补事实，消费者更换了新的消费组；收据表因此出现 at-least-once 重复行，`uniqExact(event_id)` 仍是逻辑事件数，`ReplacingMergeTree` 会按 consumed_at 合并。这个重复是重放的预期行为，不是事件重复采集。

## Phase 2c：PostgreSQL 影子事实

2026-10-30 13:43 CST 在 ClickHouse 事实之后追加 PostgreSQL 事实级影子表：

- 表 `discovery_service_facts_shadow`，迁移 `202_discovery_facts_shadow.sql`；
- 主键 `(device_key, fact_key)`，按 `version`（observed_at 纳秒）和 `event_id` 只允许新版本覆盖旧版本；
- 同一批内先按 `(device_key,fact_key)` 去重，避免 PostgreSQL `ON CONFLICT` 在同一语句中重复命中；
- 仍是事实级影子，不是最终 `device_current`；设备当前态还需要把多个事实合并后单独建表。

2026-10-30 13:44 CST 核验：

| 指标 | 值 |
| --- | --- |
| 消费组 | `ps-discovery-eventbus-facts-pg-v1`，Stable，TOTAL-LAG=0 |
| ClickHouse 事实 `count() FINAL` | 810 |
| ClickHouse 唯一 `(device_key,fact_key)` | 810 |
| PostgreSQL 事实行数 | 810 |
| PostgreSQL 唯一 `(device_key,fact_key)` | 810 |
| 涉及设备 | 482 |
| 收据唯一事件数 | 40,135 |

ClickHouse 和 PostgreSQL 的事实键、行数和设备数一致；消费者重启后仍为 Stable、TOTAL-LAG=0，PG 行数保持 810。

PG 样本：

```text
device_key=e4340538084b1009b26e6c9da4c24598
fact_key=bf6849d3fc7752b17c5c9c4091b6bea4...
event_id=stream-7f45aa5ad41ec6d1632663e36ea2d2cf
protocol=dns_sd
ip=10.202.6.139
observed_at=2026-10-30 05:43:35.035156+00
```

## Phase 2d：影子设备当前态

2026-10-30 13:46 CST 上线了从影子事实增量聚合的设备当前态：

- 表 `discovery_device_current_shadow`：`device_key` 主键、`last_seen`、`fact_count`、`facts JSONB`；
- 状态表 `discovery_device_current_shadow_state` 记录已处理到的 `updated_at`；
- `cmd/event-bus-current-shadow` 每 5 秒只选取 `discovery_service_facts_shadow.updated_at` 有变化的设备，再对该设备的事实做聚合，不是每次全表重建；
- 服务 `proxy-sentinel-eventbus-current-shadow.service`，enabled + active；
- 迁移 `203_discovery_device_current_shadow.sql`，checksum `8cb1a067432288c5a2495c78f6fd93e16cd59798192cd90623abc66905757708`；
- 迁移 `204_discovery_device_current_valid_facts.sql`，checksum `8102eabda21db322fabe75f850b975636ccee48a97b3c78dd0a77126131549b9`。

2026-10-30 13:47 CST 核验：

| 指标 | 值 |
| --- | --- |
| 当前态设备数 | 547 |
| 有效事实 `sum(fact_count)` | 366 |
| 过期/撤销事实 `sum(expired_fact_count)` | 552 |
| 事实表行数 | 918 |
| 无有效事实但仍保留的设备 | 337 |
| 当前态首次重算 | upserted=547 |
| 当前态聚合服务 | active、enabled |

`sum(fact_count) + sum(expired_fact_count) = 918`，与事实表行数一致；`facts` 只包含 `withdrawn=false AND (valid_until IS NULL OR valid_until > now())` 的事实，`fact_count` 与 JSONB 键数一致。没有有效事实的设备仍保留 `last_seen`，`facts` 为空对象，读取方需要明确这种状态。

边界：

- 当前态 `facts` 已过滤 withdrawn/过期事实，过期数量单独记录在 `expired_fact_count`；最终读取语义仍未切换；
- 不是最终 `device_current`，没有接 Redis，没有接读取路径；
- 聚合依赖 `updated_at` 高水位；时钟/并发提交的极端顺序仍需做故障测试；
- 当前态表不是新方案的读模型切换点。

## 新旧影子比对（只读）

2026-10-30 13:48 CST 对 PostgreSQL 旧当前态做了只读计数比对：

| 对比项 | 结果 |
| --- | --- |
| 旧 `discovery_device_state_v2` 设备数 | 27,560 |
| 新 `discovery_device_current_shadow` 设备数 | 532 |
| 新旧设备键交集 | 176 |
| 仅新影子有的设备 | 356 |
| 新旧事实键交集 | 218 / 889 |

这不是“新旧已一致”。旧表包含长期历史设备；新当前态只覆盖本次 Kafka 新鲜窗口，且旧投影本身存在积压/未物化，因此仅新影子有的 356 个设备需要逐批审计，不能直接判定哪边正确，也不能据此切读。下一步必须做设备键和事实键的逐条差异审计，并至少观察一个完整影子窗口。

## 下一阶段

Phase 2e 才进入最终当前态和读取验证：

1. 写 `discovery_receipts`、`discovery_changes`、`discovery_facts_current`；
2. 建 PostgreSQL `device_current` 影子表，只写变化设备；
3. Redis 热状态和版本比较；
4. 新旧投影结果按设备/事件比对；
5. 24 小时无缺口后再讨论读取切换。

本阶段不宣称上述任何一项已完成。
