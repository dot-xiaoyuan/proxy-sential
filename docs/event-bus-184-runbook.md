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

## 已知边界

- 身份影子是最近 24h 活跃集合，不是全量 644k 历史；
- 识别覆盖是新鲜起点，24h 内仍有约 18h 历史缺口；
- 旧表尚未退役；
- 184 单节点 Redpanda/HDD 不是生产容量验收结论；
- 旧控制面 D 状态进程需要维护重启清理。
