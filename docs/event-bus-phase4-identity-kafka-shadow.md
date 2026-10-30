# 身份会话 Kafka 影子链路

状态：真实身份会话更新已经进入 Kafka，并写入了身份会话影子表；身份 account/endpoint 读路径已切到影子并保留旧路径回退。

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

## 身份读切换（2026-10-30 20:12 CST）

之前 account identity 一直超时，根因不是影子查询，而是：

- 旧 `proxy-sentinel-control-plane.service` 仍然 active，PID 449389 持有 `0.0.0.0:18080`；
- 新 `proxy-sentinel-control-plane-eventbus.service` 一直 `bind: address already in use`，反复重启；
- 实际服务 18080 的是旧 r24 二进制，新的影子读开关从未生效。

处理：

- 停止并 disable 旧 `proxy-sentinel-control-plane.service`；
- 确认 18080 空闲；
- 启动并 enable 新 `proxy-sentinel-control-plane-eventbus.service`；
- **enable** `PROXY_SENTINEL_IDENTITY_EVENTBUS_READ=true`；
- 新控制面进程 `/opt/proxy-sentinel/releases/2026.10.30-eventbus-p2/bin/proxy-sentinel-identity-eventbus` 持有 18080。

切读验证：

```text
/discovery/devices                200, freshness.source=eventbus
/accounts/093360/identity         200, 0.037s, 200 sessions, 1 endpoint
/endpoints/<mac>/identity         200, 0.024s, 1 session, 1 account
```

控制面日志：

```text
identity shadow account start account=093360
identity shadow account done account=093360 ok=true err=<nil> elapsed=34.889047ms
```

身份 account/endpoint identity 现在直接查 `identity_session_shadow`，不再先执行旧的 account_sessions/IP-history 重查询；影子没有命中时仍回退旧 reader。

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

## 身份读覆盖尝试与回退

2026-10-30 20:03 CST 曾把 `PROXY_SENTINEL_IDENTITY_EVENTBUS_READ=true` 启用，在旧 `GetAccountIdentity` / `GetEndpointIdentity` 返回后叠加 Kafka 影子 session。

实测失败：

- `/api/v1/accounts/<id>/identity` 先执行旧的 account identity 查询；
- 旧查询出现 `WITH ids AS (...)` 的长时间 IO 等待，超过 1 分钟；
- 只叠加影子不能绕过旧查询，反而继续占用 184 的 PG/HDD；
- 已取消查询、删除临时测试会话，并把 `PROXY_SENTINEL_IDENTITY_EVENTBUS_READ` 从控制面单元移除；
- 控制面恢复 active，`/readyz=200`；
- 影子 API 和 Kafka 消费链路不受影响。

结论：身份读切换不能靠“旧查询后叠加影子”，必须**直接替换** `GetAccountIdentity` / `GetEndpointIdentity` 的读取实现，或者先让旧查询只读小表。当前身份影子仍只通过 `/v1/shadow/identity/*` 只读 API 暴露。

## 直接影子读取尝试（已关闭）

第二次读切换改为完全绕过旧 `GetAccountIdentity` / `GetEndpointIdentity`：

- 新增 `GetAccountIdentityShadow` / `GetEndpointIdentityShadow`，只查 `identity_session_shadow`；
- 增加 account/endpoint 影子索引迁移 `211_identity_shadow_lookup_indexes.sql`；
- 控制面 `PROXY_SENTINEL_IDENTITY_EVENTBUS_READ=true` 时直接调用影子方法，不再先跑旧查询。

实测：

- endpoint identity 返回 200，读取 17 个 session；
- account identity 仍然 8 秒超时；
- 请求期间 PG 活跃查询是 commit/IO，没有看到完整的影子 account 查询输出；
- 为避免继续占用 184，已再次关闭开关并重启控制面；
- 控制面恢复 active，`/readyz=200`。

结论：direct shadow 代码已保留但默认关闭；account 路径仍需单独 profiling（认证/锁等待/影子查询计划），不能直接启用。

## 最近 IP/接入历史

2026-10-30 20:15 CST 身份影子读返回的 profile 增加了从影子 session 派生、限定最近窗口的历史：

- `ip_history`：按 endpoint+IP+MAC+source 去重；
- `access_history`：按 endpoint+VLAN+NAS IP 去重；
- 首次/末次时间取影子 session 的 started/last_confirmed；
- 不再查旧的 IP/access 历史大表。

验证：

```text
account 093360: 200 sessions, ip_history=1, access_history=1
endpoint <mac>: 1 session, ip_history=1, access_history=1
```

这里的 history 是影子窗口内的推导历史，不是旧表全量历史。

## 端点注册/归属字段

2026-10-30 20:18 CST 端点影子读增加 `endpoint_entities` 主键查询，只补注册/归属字段，不跑旧身份历史 join：

- `registration_status`
- `owner_account`
- `owner_name`
- `owner_department`
- `asset_tag`
- `ownership_class`
- `registered_at`
- `registration_note`
- `merge_status`
- `merged_into_endpoint_id`
- `split_from_endpoint_id`
- `registration_updated_at`

验证 endpoint identity 返回 200，字段包含 `registration_status=unregistered`、`owner_account=092962`、`merge_status=active`。

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
