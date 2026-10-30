# 事件总线 Phase 2：影子收据消费者

状态：已在 184 上线运行，但**只写影子收据**；不改读取路径，不写 PostgreSQL 当前态，不写 Redis，不做新旧投影比对。总体方案见 [高性能流式存储与投影方案](high-performance-streaming-architecture-20261030.md)。

## 目标与边界

Phase 1 已证明真实发现事件能写入 Redpanda。本阶段只验证下一段：

```text
ps.discovery.events.v1
  -> Go consumer group（有界批次）
  -> ClickHouse eventbus_discovery_receipts（影子收据）
  -> Kafka offset commit
```

本阶段**不做**：

- `discovery_changes`、`discovery_facts_current`；
- PostgreSQL `device_current` 影子表；
- Redis 热状态和版本比较；
- 新旧投影结果比对；
- 读取切换、旧表退役；
- 生产多 broker、TLS/SASL、容量验收。

因此本阶段的“跑通”只代表 Kafka → 消费者 → ClickHouse 收据链路可用，不代表完整新存储架构已上线。

## 实现

| 组件 | 位置 |
| --- | --- |
| Kafka 消费者、批次、offset 提交 | `internal/eventbus/projector.go` |
| ClickHouse HTTP 收据写入 | `internal/eventbus/clickhouse_receipts.go` |
| 消费者入口 | `cmd/event-bus-consumer/main.go` |
| ClickHouse 表迁移 | `migrations/clickhouse/057_eventbus_discovery_receipts.sql` |
| systemd 单元 | `deploy/systemd/proxy-sentinel-eventbus-consumer.service` |

消费语义：

- 固定消费组 `ps-discovery-eventbus-shadow-v1`，从最早 offset 开始；
- 一次最多 1,000 条或 500 ms 批次；
- 先写 ClickHouse，成功后提交该批 Kafka offset；
- 重复消费由 `eventbus_discovery_receipts` 的 `ReplacingMergeTree` 和 `event_id` 去重；
- 历史非法消息不会阻塞整个消费者：记录日志、跳过并随批次提交；生产中应改为 DLQ，这是本阶段明确的测试边界；
- 遇到 sink/commit 错误直接退出，由 systemd 重启并从已提交 offset 重放。

表结构使用 `ORDER BY (device_key, observed_at, event_id)`、`PARTITION BY toYYYYMM(observed_at)`、`TTL 30 天`，`envelope` 使用 ZSTD 压缩。该表是影子收据，不是新的权威原文表。

## 184 部署

- 发布目录：`/opt/proxy-sentinel/releases/2026.10.30-eventbus-p2`
- 二进制 SHA256：`f034adfc4c30d40eb33c2d9b180b54990628df21dc5640491873dcb0ffd4f29a`
- 源码提交：`5d3b542b`
- systemd：`proxy-sentinel-eventbus-consumer.service`，enabled + active
- 环境：复用 `/opt/proxy-sentinel/config/runtime.env` 中的 `PROXY_SENTINEL_CLICKHOUSE_DSN`，不在命令行和文档中展开凭据
- 表迁移：`057_eventbus_discovery_receipts.sql` 已创建；迁移账本 checksum 为 `0405391d8f77ad8e7cafeb30e765c4f4fed286795f4bbb96bf9dab75eab468b8`

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

## 下一阶段

Phase 2b 才进入真正的发现投影：

1. 写 `discovery_receipts`、`discovery_changes`、`discovery_facts_current`；
2. 建 PostgreSQL `device_current` 影子表，只写变化设备；
3. Redis 热状态和版本比较；
4. 新旧投影结果按设备/事件比对；
5. 24 小时无缺口后再讨论读取切换。

本阶段不宣称上述任何一项已完成。
