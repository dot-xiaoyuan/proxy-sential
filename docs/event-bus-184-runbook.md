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

### 2026-10-30 22:52 最终验证

在 500 事件段、capture `SinkTimeout=30s`/`ProjectionRetryTimeout=30s`、worker `SinkTimeout=30s`/`ProjectionRetryTimeout=120s` 下：

```text
discovery max(last_seen) age ≈ 40s
activity as_of age ≈ 2m39s（5m 桶正常）
application cursor age ≈ 5.7s
discovery group TOTAL-LAG=0
identity group  TOTAL-LAG=0
EVE rotate timer active
load ≈ 18–22
```

旧 949/987 事件慢段已逐个 commit，发现数据恢复当前。

## 2026-10-30 23:35 采集链路恢复记录

- 启用并启动 `proxy-sentinel-handshake-signal.service`；`handshake.jsonl` 从 1.615 GB 继续增长，handshake sidecar 恢复输入。
- EVE 轮转服务去掉 `logrotate -f`，改为按 500 MB 阈值轮转；避免每分钟强制轮转导致 EVE ingest 持续报 source failed。重启后 EVE ingest 不再报错。
- DHCP binding R8 的旧 cursor 指向已轮转 inode，导致 `unconfirmed file gap or truncation`；
  - 备份旧 cursor；
  - 将 cursor 重新定位到当前 `device_dhcp_binding.log` inode 的 0 偏移；
  - 同步修正 `stream_source_cutovers` 的 file_id/start_offset；
  - 改用带 30s projection 预算的 capture 二进制；
  - R8 恢复 active，DHCP 流式段开始 commit。
- 发现页面继续使用合并新鲜状态；eventbus current 旧段仍在后台排空。

注意：DHCP cursor/cutover 是现场修复动作，已保留旧 cursor 备份；后续正式轮转应走 prepare/rotation-archive 审计流程，不再手工改 cursor。

## 2026-10-30 23:43 发现流式新代次切流

旧被动发现 epoch `discovery-layered-r7-20261028` 的投影队列持续积压，导致 eventbus current / DNS-SD 滞后。按固定新起点完成切流：

- 旧 epoch 使用 `ingest stream-cancel` 审计关闭，状态 `closed_cancelled_unprocessed`，旧 journal 保留；
- 新 epoch `discovery-fresh-20261030T154207Z` 通过 `discovery-worker --mode=stream-prepare` 激活；
- 新 journal `/var/lib/proxy-sentinel/discovery-fresh-20261030T154207Z`；
- discovery service 切换到新 journal，旧 1000 事件段不再投影；
- 新段 17 events 的 projection/commit 约 2s。

切流后：

```text
stream_discovery_device_state age ≈ 9s
discovery_device_current_shadow age ≈ 11s
stream facts dns_sd ≈ 11s
stream facts ssdp ≈ 1m
discovery group TOTAL-LAG=0
```

旧历史缺口保留在已关闭 epoch 和审计清单中，不计作完成。

## 2026-10-30 23:52 后续收敛

- 在发现采集配置中启用 `ssdp` 和 `lldp`（原先仅 `dns_sd`）；
- DHCP R8 追平，`stream_discovery_facts.dhcp` 已到秒级；
- `discovery_service_facts_shadow` 的 SSDP 已随新 epoch 恢复当前，DNS-SD/SSDP 事实影子为秒级；
- ClickHouse 系统日志清理：
  - `system.text_log` 从约 142 GiB 清空；
  - `system.query_log` 从约 89 GiB 清空；
  - 根盘从 91%（157 GB 可用）降到 77%（404 GB 可用）；
- LLDP 已启用，但 8 秒 `tcpdump ether proto 0x88cc` 捕获 0 包，当前环境没有 LLDP 输入；
- `discovery_service_facts_shadow` 的 DHCP/LLDP/IEEE1905 仍是旧协议影子（新 DHCP 走 R8/stream facts，页面不依赖该旧影子）。

## 2026-10-31 15:27 协议运行时接回新发现代次

发现 worker 现在在启动时：

- 重置 `discovery_protocol_runtime` 中 owner=discovery-worker 的旧计数；
- 按当前采集配置写入 owner/enabled；
- 每秒从 `stream-capture-stats/capture.stats` 更新 received/parsed/rejected/last_seen；
- 用当前解析计数刷新 admitted/last_success。

当前启用：

```text
dns_sd  enabled
ssdp    enabled
lldp    enabled（现场无 LLDP 输入）
ieee1905_client_association 尝试启用后 168 包全部 rejected，已回退 disabled
```

验证时 DNS-SD/SSDP 的 runtime 计数和 last_seen 已跟随新代次刷新。

## 2026-10-31 15:30 协议逐步开启记录

- discovery worker 已接回 `discovery_protocol_runtime`，DNS-SD/SSDP/ARP 计数和 last_seen 每秒刷新；
- 已启用：dns_sd、ssdp、lldp、arp；
- LLDP 现场 0 包；
- 尝试启用 IEEE1905 client association：168 包全部 rejected，已回退 disabled；
- DHCP 由 R8 流式链路采集，current-shadow 每 5 秒把 DHCP 的 last_seen/last_success 从活跃 stream facts 写入 runtime；
- ARP 启用后 Kafka 曾短暂 lag 492，随后回到 0。

## 2026-10-31 15:40 发现设备补全 stream-only 当前态

发现 current 表此前只包含 eventbus facts 已投影的设备，活跃 stream 状态中有约 7,984 个设备没有进入 current 表，页面总数偏低。

处理：

- current-shadow 每轮把活跃 `stream_discovery_device_state` 中 `document->>'current'='true'`、current 表不存在的设备补入 `discovery_device_current_shadow`；
- 已存在设备只提升 `last_seen`，不覆盖 eventbus 事实；
- eventbus 被动发现查询对 `fact_count=0` 的 stream-only 文档保留可见性，避免补入后在列表中再次被过滤；
- 结果：current 表 93,742 → 101,942，发现页总数 13,356 → 37,893，缺失 stream current 设备 7,984 → 2（持续补入）。

页面验证：`共 37893 个设备`，最近观测“刚刚”，无 console/page error。

## 2026-10-31 15:44 发现时间筛选语义

- 默认仍为近 24 小时；
- “全部观测时间”改为显式 `window=all`，后端映射为无窗口过滤；
- 验证 `window=all` 返回 total=102,342 当前文档；默认 24h 返回约 38,000；
- 这样默认时间语义与筛选标签一致，不再出现“全部观测时间”实际仍按 24h 过滤。

## 2026-10-31 15:47 发现设备全量查询优化

- 新增 `(device_key, protocol)` 事实索引，服务被动发现 `EXISTS` 过滤；
- “全部观测时间”返回 102k 设备，single-count 仍需约 1.4–3.6 秒；页面默认 24h 保持快速；
- 发现页仍使用 20 条游标分页，不建议把全部时间作为默认视图。

## 2026-10-31 15:50 排除历史 current 文档

`discovery_device_current_shadow` 中残留了 `document->>'current'='false'` 的历史文档（约 57,772 条），eventbus 查询曾把其中 `fact_count=0` 的设备算入发现页。

- 查询增加 `(c.document->>'current' IS DISTINCT FROM 'false')`；
- 发现页总数：24h 38,021 → 28,652；全部时间 102,342 → 43,496；
- 这些历史状态仍保留在 stream state，不删除唯一原文。

## 2026-10-31 15:52 当前表清理历史文档

current-shadow 现在会：

- 把活跃 stream 中 `current=true` 的设备在 current 表标记为 current；
- 删除 current 表中 `current=false` 且没有活跃 stream current 状态的历史文档；
- 保留 stream state 历史，不删除唯一原文。

结果：

- current 表 102,771 → 51,542；
- `current=false` 文档 59,189 → 0；
- 发现页 24h 总数 36,733，全部时间 51,572；
- 全部时间 API 从约 4s 降到约 0.53s，24h API 约 0.9s；
- 页面无 console/page error。

## 2026-10-31 15:55 发现视图收敛

- 历史 `current=false` 文档从 current 表清理后：51,695 个 current 文档；
- 发现页 24h 总数 36,860，全部时间 51,695；
- 24h / all API 均约 0.4s；
- 19,490 个 `fact_count=0` 设备没有对应 `stream_discovery_facts`，保留流式文档字段，不再视为可补齐事实；
- 6 个 stream current 设备补入竞态仍存在。

## 2026-10-31 15:58 清理空当前文档

发现 current 表仍有无 facts 且 `document='{}'` 的空文档（约 3,892 条），会出现在当前列表里。

- 一次性删除空文档；
- current-shadow 每轮清理 `fact_count=0 AND document='{}'`；
- 发现页 24h 总数 36,860 → 24,975；全部时间 51,695 → 39,762；
- 页面只保留有可展示字段的当前文档。

## 2026-10-31 16:00 空文档查询保护

即使 current 表清理存在竞态，eventbus 查询也显式排除 `document='{}'` 且 `fact_count=0` 的行，避免空设备再次出现在发现页。

当前 24h total 约 24,678，页面无空名称/空地址记录。
