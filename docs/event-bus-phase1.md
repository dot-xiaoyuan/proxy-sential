# 事件总线 Phase 1：发现影子发布

状态：代码已落盘；仅本地影子验证，未部署 184，未接入投影/Redis/ClickHouse 新表。总体方案见 [高性能流式存储与投影方案](high-performance-streaming-architecture-20261030.md)。

## 范围

Phase 1 只做一件事：被动发现的新 journal 段在完成持久化后，按事件发布到 Kafka 主题 `ps.discovery.events.v1`。读取路径、archive/search/projection lanes、PostgreSQL 和 ClickHouse 都不变。

- 开关默认关闭；关闭时不创建 Kafka 客户端、不新增失败路径。
- 影子发布是 best-effort：Kafka 不可用、队列满、编码失败或事件没有稳定 key 时只计数和限速日志，不阻塞捕获、不退出进程。
- 只覆盖新段；启动恢复的旧段仍只走原 lanes，不重复发布。
- 本阶段不消费消息、不建新表、不改读路径。

## 组件

| 位置 | 作用 |
| --- | --- |
| `internal/eventbus/config.go` | 读取影子开关、brokers、topic、队列和统计路径 |
| `internal/eventbus/envelope.go` | `schema_version=1` 的事件信封、内容哈希 |
| `internal/eventbus/producer.go` | franz-go 幂等生产者，acks=all、zstd、批量 |
| `internal/eventbus/shadow.go` | 有界非阻塞队列、后台发布、失败/丢弃计数 |
| `internal/eventbus/stats.go` | 原子写 `eventbus.stats` |
| `internal/eventbus/consumer.go` | 仅诊断/集成测试用的有界消费者 |
| `internal/discovery/stream_partition.go` | `device_key` 优先的稳定分区键和回退 |
| `internal/discovery/stream_passive_capture.go` | `CapturedSegment`，把段直接交给回调 |
| `cmd/discovery-worker/stream.go` | 初始化影子发布，接到 `onSegment` |
| `cmd/event-bus-probe` | 本地 produce/consume 探针，不打包进发布 |

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PROXY_SENTINEL_EVENT_BUS_SHADOW` | `false` | 设为 `true` 才启用影子发布 |
| `PROXY_SENTINEL_EVENT_BUS_BROKERS` | 空 | 逗号分隔，例如 `127.0.0.1:19092` |
| `PROXY_SENTINEL_EVENT_BUS_CLIENT_ID` | `discovery-<node>` | Kafka client id |
| `PROXY_SENTINEL_EVENT_BUS_DISCOVERY_TOPIC` | `ps.discovery.events.v1` | 发现域主题 |
| `PROXY_SENTINEL_EVENT_BUS_LINGER_MS` | `5` | 生产者批量等待，0—1000 |
| `PROXY_SENTINEL_EVENT_BUS_QUEUE` | `8192` | 事件级有界队列，1—65536 |
| `PROXY_SENTINEL_EVENT_BUS_MAX_RECORD_BYTES` | `921600` | 单条信封上限，64 KiB—1 MiB |
| `PROXY_SENTINEL_EVENT_BUS_STATS_PATH` | `<stream-capture-stats>/eventbus.stats` | 统计文件 |

配置错误（例如打开开关但没有 brokers）不会阻止捕获：`discovery-worker` 记录 `event-bus shadow disabled: ...`，写一份 `enabled=false` 的统计文件，然后继续运行原路径。

## 消息契约

```json
{
  "schema_version": 1,
  "event_id": "stream-...",
  "event_type": "discovery",
  "sensor_id": "ncu-184-router-pilot",
  "scope_id": "bond0-passive-pilot",
  "partition_key": "<device_key>",
  "observed_at": "2026-10-30T02:15:00.123Z",
  "accepted_at": "2026-10-30T02:15:00.456Z",
  "content_hash": "sha256:...",
  "segment_id": "<journal segment id>",
  "source": "passive-discovery",
  "source_path": "packet://bond0/passive-...",
  "event": { "...": "标准事件原文" }
}
```

分区键：

1. 可适配为发现观察时，使用 `discoveryStateKey`（设备维度）。
2. 否则回退 `scope + MAC`。
3. 再回退 `scope + IP`。
4. 最后回退 `scope + event_id`。

`partition_key_source` 通过 Kafka header 记录为 `device`/`mac`/`ip`/`event`，便于诊断，不改变事件本身。

## 本地验证

要求 Docker/OrbStack 可用；这是单节点 PLAINTEXT 验证，不是生产部署。

```bash
make eventbus-up
make eventbus-status

# 只验证总线
make eventbus-smoke

# 手动探针
go build -o bin/event-bus-probe ./cmd/event-bus-probe
bin/event-bus-probe -mode produce-sample -brokers 127.0.0.1:19092
bin/event-bus-probe -mode consume -brokers 127.0.0.1:19092 -group probe-1 -count 1

make eventbus-down
```

`make eventbus-up` 会创建 `ps.discovery.events.v1`（本地 6 分区、副本 1）。生产主题需要按容量设计预先创建，通常 24 分区、副本 3。`make eventbus-status` 默认读取 `<repo>/data/run/eventbus.stats`；如果 worker 的 spool 在别处，用 `EVENTBUS_STATS_PATH=<spool>/stream-capture-stats/eventbus.stats` 指向实际文件。

## 184 单节点部署验证

184 的 Docker 18.09 在本次部署时无法创建新容器（已有容器继续运行），因此 184 采用**主机二进制 + systemd** 的单节点 Redpanda 验证方式；本地开发仍可用 `deploy/compose/eventbus.yml` 的 Docker 方式。两种方式都只是测试拓扑。

已部署事实：

- 运行时：`redpandadata/redpanda:v25.3.18` 镜像中的 `/opt/redpanda` 发行目录，安装到 `/opt/redpanda`；`rpk version` 为 `v25.3.18`。
- 配置：`/etc/redpanda/redpanda.yaml`，Kafka `127.0.0.1:19092`、Admin `127.0.0.1:19644`、RPC `127.0.0.1:33145`，数据 `/opt/proxy-sentinel/data/eventbus/redpanda`。
- 服务：`proxy-sentinel-eventbus-host.service`，已 enable，`Restart=on-failure`，`LimitNOFILE=65536`。
- 主题：`ps.discovery.events.v1`，6 分区、副本 1。
- 验证：`rpk cluster health` 为 `Healthy: true`；`eventbus-184.sh smoke` produce/consume 通过；`cmd/event-bus-probe` 在 184 上 produce/consume 通过；`TestRedpandaShadowPublishes` 测试二进制在 184 上通过；`down`/`up`/`smoke` 完整周期通过，主题和 offset 在重启后保留。

运维命令（在 184 上）：

```bash
/opt/proxy-sentinel/scripts/eventbus-184.sh up
/opt/proxy-sentinel/scripts/eventbus-184.sh status
/opt/proxy-sentinel/scripts/eventbus-184.sh smoke
/opt/proxy-sentinel/scripts/eventbus-184.sh restart
/opt/proxy-sentinel/scripts/eventbus-184.sh logs
/opt/proxy-sentinel/scripts/eventbus-184.sh topics
/opt/proxy-sentinel/scripts/eventbus-184.sh down
```

边界与风险：

- 这是**单 broker、PLAINTEXT、回环绑定、HDD 数据目录**的测试部署；端口不对外暴露，生产必须使用 3 broker、TLS/SASL、SSD/NVMe 和容量验证。
- 配置开启 `developer_mode`，Redpanda 进程实际带 `--overprovisioned` 和 `--unsafe-bypass-fsync=true`；这降低了测试环境的持久化保证，不能用于生产。
- 184 目前只剩约 192 GB 可用，且数据库/投影共享同一块 HDD；本部署只证明“能部署、能生产消费、能重启恢复”，不证明容量或吞吐。
- Docker 18.09 的容器创建路径在这次验证中卡住，旧 Docker compose 单元已移除；旧 sandbox systemd 单元移除后仍有一个 `mount` 辅助进程处于 D 状态（孤儿），需要主机维护窗口重启才能清除；它不属于 eventbus host 服务，当前不影响 Kafka 健康。不要在同一主机同时运行 Docker 版和主机版 Redpanda。
- 部署脚本和配置在仓库的 `deploy/redpanda/redpanda.yaml`、`deploy/redpanda/eventbus-184.env.example`、`deploy/systemd/proxy-sentinel-eventbus-host.service`、`scripts/deploy/eventbus-184.sh`，便于复核和重建。

## 打开影子发布

在**本地**验证时：

```bash
export PROXY_SENTINEL_EVENT_BUS_SHADOW=true
export PROXY_SENTINEL_EVENT_BUS_BROKERS=127.0.0.1:19092
# 启动 discovery-worker --mode=stream，并保持原 journal/scope 参数
```

现场或跨主机验证前必须先补 TLS/SASL；Phase 1 没有实现安全连接，不得把本地 PLAINTEXT 配置直接带到 184。

检查：

- `eventbus.stats` 的 `published` 随新段事件数增长；
- `failed`/`dropped` 为 0，或可解释；
- 捕获日志没有新增阻塞/退出；
- `eventbus.stats` 的 `last_success` 持续前进；
- Kafka 中 `partition_key` 与事件设备一致。

## 故障行为

| 情况 | 行为 |
| --- | --- |
| 开关关闭 | 不创建 producer，不连接 Kafka |
| 配置错误 | 记录并写 disabled 统计，继续捕获 |
| broker 不可用 | 投递失败计数，限速日志，捕获继续 |
| 队列满 | 逐事件丢弃计数，`Publish` 不阻塞 |
| 事件无稳定 key | 失败计数，不伪造 key |
| 事件编码/超限 | 失败计数，不截断 |
| 进程关闭 | 关闭队列、排空、Flush（15 秒上限），超时记录 |
| 段恢复 | 旧段只走原 lanes，不重复影子发布 |

## 回退

1. 删除或设为 `PROXY_SENTINEL_EVENT_BUS_SHADOW=false`。
2. 重启 `discovery-worker`（当前 phase 1 未改 systemd 单元，沿用原服务）。
3. 可选：`make eventbus-down` 停止本地 Redpanda；`data/eventbus` 保留，便于复查。
4. 不删除 journal、不迁移数据库、不改变旧 lanes。

## 不在本阶段

- 消费者投影、ClickHouse receipts/changes/facts 表、Redis 热状态。
- PostgreSQL `session_open`/`device_current`。
- 读取切换、归档切换、NCU 其他来源接入。
- TLS/SASL、生产多 broker、持久 spool/outbox。
- 184 部署和容量验收。

这些在 Phase 2+ 单独设计、单独验收，不复用本阶段的“影子”结论。
