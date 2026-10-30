# 身份会话 Kafka 影子链路

状态：真实身份会话更新已经进入 Kafka，并写入了身份会话影子表；生产身份读路径**未切换**。

## 数据源修正

原计划从 ClickHouse `identity_signal_events_v1` 做 relay，但只读核对发现：

- `identity_signal_events_v1` 有 2,149 万行 / 5.13 GiB，最新 `received_at` 只到 2026-10-25 15:51 UTC；
- `normalized_events` 的 identity 类型最新也只到 2026-10-24 23:36 UTC；
- 现场 `account_sessions` 仍在实时更新，最新 `updated_at` 是当前时间，约 214 万行。

所以身份链路不能从陈旧 CH 表 relay，改为从 PostgreSQL `account_sessions` 做**增量变更 relay**。

## 链路

```text
account_sessions(updated_at > cursor)
  -> identity-event-relay
  -> Kafka ps.identity.events.v1 (6 partitions)
  -> identity-event-consumer
  -> identity_session_shadow
  -> identity_session_open_shadow (ended_at IS NULL)
```

## 组件

- relay：`cmd/identity-event-relay`，游标表 `identity_event_relay_state`；
- topic：`ps.identity.events.v1`，6 分区；
- consumer：`cmd/identity-event-consumer`，消费组 `ps-identity-eventbus-shadow-v1`；
- 表：`identity_session_shadow`，迁移 `209_identity_session_shadow.sql`；
- 表：`identity_endpoint_current_shadow`，迁移 `210_identity_endpoint_current_shadow.sql`；
- 视图：`identity_session_open_shadow`；
- 服务：
  - `proxy-sentinel-identity-event-relay.service`
  - `proxy-sentinel-identity-event-consumer.service`

## 验证（2026-10-30 19:58 CST）

- relay active，游标已推进到 `2026-10-30T11:58:12Z`；
- Kafka topic 6 分区均有数据；
- consumer active，消费组 `Stable`，`TOTAL-LAG=0`；
- `identity_session_shadow` 已写 322 个 session，其中 140 个 open；
- `identity_endpoint_current_shadow` 已有 188 个 endpoint；
- 实际消息包含 `session_id/account_id/endpoint_id/ip/mac/started_at/ended_at/session_status/policy_metadata`；
- 消息 key 为 session_id，保证同一会话顺序。

## 身份影子读取接口

2026-10-30 20:00 CST 在 `event-bus-shadow-api` 增加身份只读接口：

```text
GET /v1/shadow/identity/sessions?state=open&limit=50&cursor=...
GET /v1/shadow/identity/sessions/<session_id>
GET /v1/shadow/identity/endpoints?limit=50
GET /v1/shadow/identity/endpoints/<endpoint_id>
```

验证：

- 会话列表返回真实登录 session（account_id、IPv6、MAC、VLAN、NAS IP、login/logout）；
- `limit=5` 连续两页，交集为 0；
- 详情接口返回同一 session；
- endpoint 列表返回当前 endpoint 和最新 session；
- 服务 `proxy-sentinel-eventbus-shadow-api.service` active。

该接口是只读影子入口，不是控制面生产身份接口，也没有切旧会话读。

## 24h 活跃 session 引导

2026-10-30 20:02 CST 对 `account_sessions` 做了**最近 24h 开放 session** 的引导，不重放 214 万全量：

```sql
WHERE ended_at IS NULL
  AND COALESCE(last_confirmed_at,updated_at) > now()-interval '24 hours'
```

结果：

- 插入 34,947 个 session；
- `identity_session_shadow` 现有 35,247 个 session，其中 34,951 个 open；
- 从这些 open session 重建 `identity_endpoint_current_shadow`，得到 18,158 个 endpoint；
- 旧 `account_sessions` 仍有 644,004 个 open，但其中大部分是超过 24h 未确认的历史状态；新的影子只保留最近 24h 活跃集合。

这比之前的 215 个 open session 更接近可用当前态，但还不是完整 644k 历史的等价物。

## 边界

- 这是**新鲜起点**：relay 从当前 `updated_at - 1min` 开始，没有重放 214 万历史 session；
- 现场旧 `account_sessions` 有 **644,004 个 open session**，影子目前只有 140 个 open，差 643,864；
- 因此身份读路径不能切；需要先决定：
  - 是否做 open-session 快照引导（64 万行，需分批）；
  - 或接受新鲜起点并展示身份历史缺口；
- 还没有 `endpoint_current` 投影、身份读 API 切换、旧表退役。

## 下一步

1. 明确身份采用“快照引导”还是“新鲜起点”；
2. 若快照引导，按 `ended_at IS NULL` 分批复制到 `identity_session_shadow`，记录进度；
3. 建 `endpoint_current_shadow`；
4. 对比旧读路径后，再讨论切身份会话读。
