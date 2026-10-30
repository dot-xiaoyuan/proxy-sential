# 事件总线 Phase 2：影子收据消费者

状态：Phase 2a 影子收据消费者和 Phase 2b 影子事实表均已在 184 上线；不改读取路径，不写 PostgreSQL 当前态，不写 Redis，不做新旧投影比对。总体方案见 [高性能流式存储与投影方案](high-performance-streaming-architecture-20261030.md)。

## 目标与边界

Phase 1 已证明真实发现事件能写入 Redpanda。本阶段只验证下一段：

```text
ps.discovery.events.v1
  -> Go consumer group（有界批次）
  -> ClickHouse eventbus_discovery_receipts（影子收据）
  -> ClickHouse eventbus_discovery_facts_shadow（影子事实，Phase 2b）
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
| systemd 单元 | `deploy/systemd/proxy-sentinel-eventbus-consumer.service` |

消费语义：

- 当前事实阶段使用消费组 `ps-discovery-eventbus-facts-shadow-v1`，从最早 offset 开始；收据阶段旧组 `ps-discovery-eventbus-shadow-v1` 保留作历史；
- 一次最多 1,000 条或 500 ms 批次；
- 先写 ClickHouse 收据，再写影子事实，两者成功后提交该批 Kafka offset；
- 重复消费由 `eventbus_discovery_receipts` 的 `ReplacingMergeTree` 和 `event_id` 去重；
- 历史非法消息不会阻塞整个消费者：记录日志、跳过并随批次提交；生产中应改为 DLQ，这是本阶段明确的测试边界；
- 遇到 sink/commit 错误直接退出，由 systemd 重启并从已提交 offset 重放。

收据表使用 `ORDER BY (device_key, observed_at, event_id)`、`PARTITION BY toYYYYMM(observed_at)`、`TTL 30 天`，`envelope` 使用 ZSTD 压缩。该表是影子收据，不是新的权威原文表。事实表使用 `ORDER BY (device_key, fact_key)`、`ReplacingMergeTree(version)`，每个事实保留最新观测。

## 184 部署

- 发布目录：`/opt/proxy-sentinel/releases/2026.10.30-eventbus-p2`
- 二进制 SHA256：`c38ba1a7d8cc0d34b795c7194738b60359d6c840e0e79d06361b9e3b55f2b504`
- 源码提交：`a3ef42b3`
- systemd：`proxy-sentinel-eventbus-consumer.service`，enabled + active
- 环境：复用 `/opt/proxy-sentinel/config/runtime.env` 中的 `PROXY_SENTINEL_CLICKHOUSE_DSN`，不在命令行和文档中展开凭据
- 表迁移：`057_eventbus_discovery_receipts.sql` 与 `058_eventbus_discovery_facts_shadow.sql` 已创建；账本 checksum 分别为 `0405391d8f77ad8e7cafeb30e765c4f4fed286795f4bbb96bf9dab75eab468b8`、`b31a1924207abbb66b13ed0b6bc452526afd1a9d94befcc47f34e473e60cc71d`

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

## 下一阶段

Phase 2c 才进入真正的发现当前态：

1. 写 `discovery_receipts`、`discovery_changes`、`discovery_facts_current`；
2. 建 PostgreSQL `device_current` 影子表，只写变化设备；
3. Redis 热状态和版本比较；
4. 新旧投影结果按设备/事件比对；
5. 24 小时无缺口后再讨论读取切换。

本阶段不宣称上述任何一项已完成。
