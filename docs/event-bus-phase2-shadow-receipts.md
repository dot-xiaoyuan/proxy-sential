# 事件总线 Phase 2：影子收据消费者

状态：Phase 2a 收据、Phase 2b ClickHouse 影子事实、Phase 2c PostgreSQL 影子事实、Phase 2d PostgreSQL 影子设备当前态、Phase 2e Redis 热态、Phase 2f Redis/PG 读取一致性、Phase 2g 只读影子 API 均已在 184 上线；不改生产读取路径，不写最终 `device_current`；已做只读新旧计数/新鲜度比对，未做读取切换。总体方案见 [高性能流式存储与投影方案](high-performance-streaming-architecture-20261030.md)。

## 目标与边界

Phase 1 已证明真实发现事件能写入 Redpanda。本阶段只验证下一段：

```text
ps.discovery.events.v1
  -> Go consumer group（有界批次）
  -> ClickHouse eventbus_discovery_receipts（影子收据）
  -> ClickHouse eventbus_discovery_facts_shadow（影子事实，Phase 2b）
  -> PostgreSQL discovery_service_facts_shadow（影子事实，Phase 2c）
  -> PostgreSQL discovery_device_current_shadow（影子当前态，Phase 2d）
  -> Redis ps:disc:current:*（热态缓存，Phase 2e）
  -> event-bus-shadow-api（只读校验 API，Phase 2g）
  -> Kafka offset commit
```

本阶段**不做**：

- `discovery_changes`、最终版 `discovery_facts_current`（当前只有 `eventbus_discovery_facts_shadow`，不是完整事实集合成）；
- PostgreSQL `device_current` 影子表；
- 读取路径使用 Redis（当前只写热态缓存，不读）；
- 读取切换前的完整新旧差异审计（当前只有只读计数/新鲜度比对）；
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
| Redis 热态配置 | `deploy/redis/redis-eventbus.conf` |
| Redis systemd 单元 | `deploy/systemd/proxy-sentinel-eventbus-redis.service` |
| 只读影子 API | `cmd/event-bus-shadow-api/main.go` |
| 只读 API systemd 单元 | `deploy/systemd/proxy-sentinel-eventbus-shadow-api.service` |
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
- 当前态聚合二进制 SHA256：`137760ddfe9c0d05494e13f4bd0155cb2bf7b6278bcf5cbd6f6eea9cb12aa7d4`，源码提交 `ab141a4d`
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
- 不是最终 `device_current`，没有接读取路径；Phase 2e 之后 Redis 只作为写缓存，不参与查询；
- 聚合依赖 `updated_at` 高水位；时钟/并发提交的极端顺序仍需做故障测试；
- 当前态表不是新方案的读模型切换点。

## Phase 2e：Redis 热态

2026-10-30 13:58 CST 部署了独立的 Redis 热态缓存：

- 运行时：Redis `8.0.2`，从现有镜像提取的主机二进制，安装到 `/opt/redis`；依赖库放在 `/opt/redis/lib`；
- 监听：`127.0.0.1:16401`，只绑回环；
- 配置：`/etc/redis-eventbus.conf`，无 RDB/AOF、`maxmemory 512mb`、`allkeys-lru`；
- 服务：`proxy-sentinel-eventbus-redis.service`，enabled + active；
- 聚合器启动时先 warm 全部当前态设备，再对变化设备增量写 Redis；
- key 前缀：`ps:disc:current:<device_key>`；value 是当前态 JSON；TTL 5 分钟；
- PostgreSQL 仍是持久化真值，Redis 只是缓存；Redis 重启后需要聚合器重 warm 或重启聚合器恢复。

2026-10-30 13:58 CST 核验：

| 指标 | 值 |
| --- | --- |
| Redis 当前态 key 数 | 580 |
| PostgreSQL 当前态设备数 | 580 |
| 有效事实 | 397 |
| 过期/撤销事实 | 575 |
| 单个 key TTL | 约 288 秒（5 分钟 TTL 的剩余值） |
| 消费组 | Stable，TOTAL-LAG=0 |

Redis value 样本：

```json
{"device_key":"95c9332008b21cb3731903c8bdd6928d","expired_fact_count":1,"fact_count":0,"facts":{},"last_seen":"2026-10-30T05:21:36.14419Z","updated_at":"2026-10-30T05:50:43.718727Z"}
```

Redis key 数与 PostgreSQL 当前态设备数一致；TTL 已生效。当前 Redis 只写不读，没有改变任何查询路径。

## Phase 2f：Redis 读取一致性

2026-10-30 14:00 CST 新增只读检查命令 `cmd/event-bus-read-shadow`：

- 逐设备读取 PostgreSQL `discovery_device_current_shadow`；
- 读取 Redis `ps:disc:current:<device_key>`；
- 比较 device_key、last_seen、fact_count、expired_fact_count、facts、updated_at；
- 发现 missing/mismatch 时退出非零。

184 实测：

```text
checked=580 missing=0 mismatches=0
```

说明 Redis 缓存当前与 PG 影子当前态一致。该命令仍是一次性只读校验，不是控制面读取接口，也没有切换任何查询路径。

## Phase 2g：只读影子 API

2026-10-30 14:01 CST 上线了独立的只读影子 API，不改控制面生产路由：

- 监听 `127.0.0.1:18084`，只绑回环；
- `GET /healthz` 检查 PostgreSQL 和 Redis；
- `GET /v1/shadow/current/<device_key>` 返回当前态；
- 优先读 Redis，未命中时回退 PostgreSQL；
- 响应头 `X-Shadow-Source: redis|postgres` 标明来源；
- 服务 `proxy-sentinel-eventbus-shadow-api.service`，enabled + active；
- 二进制 SHA256 `705b9723d9f17dd9811d6997f350c1a13fdb742232eb0749221fe086988a0766`，源码提交 `0f30aa31`。

验证：

```text
GET /healthz -> 200 {"status":"ok"}
GET /v1/shadow/current/95c933... -> 200, X-Shadow-Source: redis
删除该 Redis key 后 -> 200, X-Shadow-Source: postgres
重启 current-shadow 做 warm -> key 恢复，API 再次返回 redis
```

Redis 命中值和 PostgreSQL 回退值的字段一致；单 key TTL 约 5 分钟。这个 API 只是新方案的只读验证入口，不是控制面生产读接口，也没有切换任何查询路径。

## 新旧影子比对（只读）

先纠正一个比对基线：184 的 `PROXY_SENTINEL_DISCOVERY_V2=true`，控制面 `/discovery/devices` 实际走 `DevicesState`，读的是 **`stream_discovery_device_state` + `stream_discovery_facts` 的新鲜流式投影**，不是已停止更新的 `discovery_device_state_v2`。旧表 27,560 个设备、最后更新 2026-10-24，只是历史遗留，不能作为生产读路径的真值。

以实际读路径为基线重新核对：

| 指标 | 结果 |
| --- | --- |
| 活跃 `stream_discovery_device_state` 去重设备数 | 87,591 |
| 新 `discovery_device_current_shadow` 设备数 | 606 |
| 新影子与活跃流式状态有交集的设备 | 559 |
| 仅新影子有的设备 | 47 |
| 新影子覆盖范围 | 本次 Kafka 新鲜窗口 |

结论：

- 新影子与新鲜流式投影在近期设备上高度重合（559/606）；
- 但活跃流式状态有 87,591 个历史设备，新影子只有 606 个，直接切读会丢失大量历史可见设备；
- 之前用 `discovery_device_state_v2` 得出的“381 个新设备、旧投影 6 天没更新”只能说明遗留表状态，不能说明生产读路径；
- 新方案要落地，必须先做受控回填（或由用户明确选择新鲜起点并展示历史缺口），再做完整窗口比对；当前不能切读。

## Phase 2h：全量回填与当前态对齐

2026-10-30 14:13 CST 从活跃 `stream_discovery_facts` 做了受控回填：

- 回填前影子事实 1,017 行；
- 活跃流式事实 105,855 行；
- 回填插入 105,010 行，回填后影子事实 106,013 行；
- 影子事实覆盖设备 87,638 个；
- 重置当前态游标后全量重算，当前态 87,638 个设备；
- Redis warm 87,638 个 key，`used_memory=42.39M`。

与生产实际读路径对齐：

| 指标 | 结果 |
| --- | --- |
| 活跃 `stream_discovery_device_state` 去重设备 | 87,591 |
| 新当前态设备 | 87,638 |
| 交集 | 87,591 |
| 仅新影子设备 | 47 |
| 活跃流式设备被新影子覆盖 | **87,591 / 87,591** |

也就是说，生产当前态里的每个设备都已经在新影子中；新影子额外包含 47 个本次 Kafka 新鲜窗口设备。

检查：

```text
event-bus-read-shadow --limit 1000
checked=1000 missing=0 mismatches=0
```

Redis key 数与 PG 当前态设备数一致，消费组仍为 Stable、TOTAL-LAG=0。

这一步解决了“新影子只有几百设备、切读会丢历史”的问题；但读取接口仍未切换，当前只完成全量数据对齐。

## Phase 2i：影子列表读取

2026-10-30 14:16 CST 为只读影子 API 增加分页列表：

- `GET /v1/shadow/devices?limit=50&window=24h&cursor=...&search=...`
- 基于 `discovery_device_current_shadow` 分页；
- 对每个设备左连接活跃 `stream_discovery_device_state` 的 document，保留完整展示字段；
- 新影子 47 个无旧 document 的设备返回最小 document；
- 游标严格按 `(last_seen DESC, device_key ASC)`，过滤条件：
  - `last_seen < cursor_time`
  - 或 `last_seen = cursor_time AND device_key > cursor_key`
- 修复了初版游标只排除 cursor 设备、导致跨页重复的问题。

验证：

```text
limit=100 连续 3 页：300 行，unique=300
search=10.163.48.87：1 行
```

当前影子数据：

```text
当前态设备 87,638
活跃流式设备 87,591
覆盖 87,591 / 87,591
仅新影子设备 47
Redis keys 87,638
```

该列表 API 仍是独立只读入口，不是控制面 `/discovery/devices`，也没有切换生产读路径。

## Phase 2j：控制面发现读切换

2026-10-30 14:20 CST 将 `/discovery/devices` 切到事件总线当前态：

- 新增 `internal/discovery.DevicesEventBus`，从 `discovery_device_current_shadow` 分页，并左连接活跃 `stream_discovery_device_state` 的 document 保留展示字段；
- 控制面开关 `PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ=true` 时走新方法，否则保留原 `DevicesIndexed`/`DevicesState`；
- 新二进制：`/opt/proxy-sentinel/releases/2026.10.30-eventbus-p2/bin/proxy-sentinel-eventbus`；
- 新 systemd 单元：`proxy-sentinel-control-plane-eventbus.service`，enabled + active，监听 `0.0.0.0:18080`；
- 旧 `proxy-sentinel-control-plane.service` 已 disabled，保留为回退入口。

验证：

```text
/readyz -> 200
/ -> 200
DevicesEventBus 集成测试（184 PostgreSQL）-> PASS
分页 cursor 不重复
```

说明：

- 控制面 `/discovery/devices` 需要登录，未认证 curl 返回 401，这是预期；读方法本身已用 184 DB 集成测试验证；
- 新单元没有 `ProtectSystem`/`ReadWritePaths` sandbox，因为旧单元在重启时再次触发 systemd mount D 状态死锁；旧单元已 disabled，新单元正常服务；
- 旧单元留下的 D 状态进程 PID 147901 仍在，需重启主机才能清除；它不占用 18080，不影响新控制面；
- 读路径优先使用新当前态，历史设备 document 从活跃流式状态补齐；新 Kafka 事件由 shadow 当前态提供最新行。

## 下一阶段

剩余工作：

1. 观察切换后的 `/discovery/devices` 实际查询延迟、错误率和分页/筛选结果；
2. `discovery_changes`；
3. 对 47 个仅新影子设备做字段/身份审计；
4. 观察一个完整影子窗口并做最终当前态语义定稿；
5. 旧单元/旧表退役与回退演练。

上述 1—4 尚未全部完成，因此不能切读。
