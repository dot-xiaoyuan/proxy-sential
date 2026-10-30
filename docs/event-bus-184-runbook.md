# 184 事件总线运行手册

## 拓扑

```text
发现捕获 -> Redpanda 127.0.0.1:19092
  -> discovery consumer -> ClickHouse receipts/facts + PostgreSQL facts/current
  -> current-shadow -> Redis 127.0.0.1:16401
  -> 控制面 /discovery/devices

account_sessions(updated_at)
  -> identity relay -> ps.identity.events.v1
  -> identity consumer -> identity_session_shadow / endpoint current
  -> 控制面 account/endpoint identity

识别分钟服务 -> recognition_coverage_minute_shadow
  -> 控制面 fingerprint coverage
```

## 健康检查

在 184 执行：

```bash
/opt/proxy-sentinel/scripts/eventbus-184-health.sh
```

脚本检查：

- 新旧控制面、识别服务、Kafka、Redis、consumer、relay 状态；
- Redpanda cluster health；
- discovery / identity consumer group lag；
- shadow API `/healthz`；
- 控制面 `/readyz`；
- 当前设备/事实/身份计数；
- 识别覆盖状态、可用起点和历史缺口。

2026-10-30 20:20 CST 实测：

```text
discovery lag 0
identity lag 4（瞬时）
shadow_api=200
readyz=200
current_devices=87,808
current_facts=106,522
identity_sessions=36,029
identity_open=35,148
identity_endpoints=18,160
recognition ready / available_since=2026-10-30T06:19:00Z / gap≈64,831s
```

## 服务

| 服务 | 作用 |
| --- | --- |
| `proxy-sentinel-control-plane-eventbus.service` | 新控制面，发现/身份切读 |
| `proxy-sentinel-control-plane.service` | 旧控制面，disabled |
| `proxy-sentinel-eventbus-host.service` | Redpanda |
| `proxy-sentinel-eventbus-consumer.service` | discovery consumer |
| `proxy-sentinel-eventbus-current-shadow.service` | 当前态聚合 |
| `proxy-sentinel-eventbus-redis.service` | Redis |
| `proxy-sentinel-eventbus-shadow-api.service` | 影子只读 API |
| `proxy-sentinel-identity-event-relay.service` | 身份增量 relay |
| `proxy-sentinel-identity-event-consumer.service` | 身份影子 consumer |
| `proxy-sentinel-recognition-materializer-eventbus.service` | 识别物化/覆盖切读 |
| `proxy-sentinel-recognition-materializer.service` | 旧识别物化，disabled |

## 页面验证（2026-10-30 20:35 CST）

- `/overview`：200，运营工作台可打开；风险统计快照仍显示 2026-10-25，属于旧的 activity 统计读模型，不是发现 eventbus 数据。
- `/devices?tab=discovery`：200，20 行，最近观测 2–5 分钟，无 console/page error；
- `/devices?tab=terminal`：200，20 行，最近观测 1 分钟；
- `/settings/rules?tab=fingerprints` → 现场覆盖：200，SSDP 193,451 条、LLDP 24 条，统计时间 20:35。

发现页曾因部分 shadow document 缺少 `capabilities/protocols/observations` 数组报 `Cannot read properties of undefined (reading 'filter')`；已由 `DevicesEventBus` 统一补空数组修复。

## 回退

### 发现回退

1. `systemctl stop proxy-sentinel-control-plane-eventbus.service`
2. `systemctl enable --now proxy-sentinel-control-plane.service`
3. 检查旧控制面 `/readyz` 和 `/discovery/devices`

### 身份回退

在 `proxy-sentinel-control-plane-eventbus.service` 中去掉：

```text
Environment=PROXY_SENTINEL_IDENTITY_EVENTBUS_READ=true
```

然后 `daemon-reload`、重启控制面。发现 eventbus 读开关保持不变。

### 识别覆盖回退

1. `systemctl stop proxy-sentinel-recognition-materializer-eventbus.service`
2. `systemctl enable --now proxy-sentinel-recognition-materializer.service`
3. 检查 `read_model_runtime_state.recognition-fresh-coverage` 是否回到旧状态

### Kafka/Redis 故障

- consumer 会重试并保留 lag；
- Redis 重启后，current-shadow 需要重新 warm/write；
- 当前态以 PostgreSQL 为准，Redis 只是缓存；
- 不要清空 Kafka topic 或 offsets 作为恢复手段。

## 新鲜起点政策（2026-10-30 用户确认）

用户明确：**不处理历史数据，从新鲜起点开始，不要求追平旧表。**

执行口径：

- 识别覆盖：`recognition_coverage_minute_shadow` 从 `2026-10-30T06:19:00Z` 起算；此前历史不回填，`history_policy=excluded_without_backfill`。
- 身份：Kafka relay 从启用时开始增量消费；另加载了最近 24h 活跃 open session 作为当前态启动快照，不重放 644k 全量历史。
- 旧 `account_sessions` / `stream_discovery_receipts` / 旧投影表只保留回退和未迁移功能使用，不作为新读路径的历史补齐目标。
- 验收只看固定起点之后的持续输入、处理延迟、失败和缺口；不宣称历史已追平。
- 不因历史缺口阻塞切读，但状态接口保留 `available_since` / `history_gap_seconds`，避免把缺口伪装成完整。

## 运营总览旧统计（已接回，追赶中）

`/overview` 曾停在 `2026-10-25` 快照。原因是 legacy normalized ingest 在 2026-10-30 13:00 将来源转交给 stream owner，activity 输入中断。

2026-10-30 20:45 已在 event bus consumer 增加标准事件回写：

- `normalized_events` 恢复写入；
- `activity_chart_dirty_log` 已推进到当前窗口；
- `activity-v3-5m` 已从 2026-10-25 推进到 2026-10-30T12:40Z；
- `/overview` 标准事件和统计时间已恢复为当前快照；
- 仍有少量 5m/hour activity pending job 在追赶，但不是 Kafka 消息积压。

## 已知边界

- 身份影子是最近 24h 活跃集合，不是全量 644k 历史；
- 识别覆盖是新鲜起点，24h 内仍有约 18h 历史缺口；
- 旧表尚未退役；
- 184 单节点 Redpanda/HDD 不是生产容量验收结论；
- 旧控制面 D 状态进程需要维护重启清理。

## 标准事件回写与活动统计（2026-10-30 20:45 CST）

发现 event bus consumer 增加 `ClickHouseNormalizedSink`：把 envelope 中的标准事件回写到 `normalized_events`，用于恢复旧 activity/risk 统计的输入；这不是重新启用 legacy 文件 ingest。

验证：

- `activity_chart_dirty_log` 已从 2026-10-25 推进到 `2026-10-30T12:48:57Z`；
- `activity-v3-5m` 已推进到 `2026-10-30T12:40:00Z`；
- `/overview` 的 stats 从 2026-10-25 变为当前时间附近，标准事件已出现；
- 仍有 pending 的 5m/hour activity job，但这是统计窗口的延迟，不是 Kafka 消息积压；
- discovery/identity consumer lag 仍为 0。

后续需要让 activity worker 自动追赶 5m/hour，而不是依赖人工 nudge。

## 2026-10-30 22:30 发现投影卡段修复

发现设备数据曾滞后 45 分钟。根因是 discovery worker 的 projection 重试预算只有 8 秒，慢段 `write_receipts` 约 7–24 秒，导致同一段反复超时、无法 commit。

处理：

- `cmd/discovery-worker/stream.go` 的 `ProjectionRetryTimeout` 从 8s 提升到 30s；
- 重新构建并部署到实际运行的 release 路径 `event-bus-p1/bin/discovery-worker`；
- 重启 discovery worker；
- 暂时停止 Suricata/EVE ingest，避免 ClickHouse 写入竞争继续拖慢投影。

结果：

- 卡住的 segment 已 commit；
- `discovery_device_current_shadow.max(last_seen)` 从 13:31 推进到 14:29；
- 数据年龄从 45 分钟降到约 2–3 分钟；
- discovery/identity Kafka lag 仍为 0。

Suricata/EVE 当前暂停；应用访问页保留已产生的数据。后续若重新开启，需要先限制 EVE 事件类型/速率，避免再次拖慢发现投影。

## 2026-10-30 22:40 发现投影恢复

继续处理发现滞后：

- 流式段事件上限从 1000 降到 500，降低单段投影耗时；
- 流式采集 `SinkTimeout` 提到 30s、`ProjectionRetryTimeout` 提到 30s；
- discovery worker `ProjectionRetryTimeout` 提到 120s，覆盖历史 1000 事件慢段；
- 重新部署到实际运行的 release 路径并重启 packet/handshake capture 和 discovery worker；
- Suricata EVE 只保留 DNS/HTTP/TLS/stats，去掉 flow/snmp 等高体积事件。

验证：

```text
discovery_device_current_shadow.max(last_seen) = 2026-10-30T14:39:44Z
now - max(last_seen) ≈ 35s
discovery group TOTAL-LAG=0
identity group  TOTAL-LAG=0
```

发现数据从滞后 45 分钟恢复到约 35 秒，慢段已 commit。
