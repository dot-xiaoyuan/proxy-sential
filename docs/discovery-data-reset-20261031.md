# 发现数据全量重置与两小时采集窗口

## 用户要求

2026-10-31 17:10 CST，用户要求清理全部历史数据，从最新数据节点开始采集分析，两小时后验收。

这是一次不可恢复的测试环境重置，没有做历史备份。

## 重置范围

已清理业务历史：

- PostgreSQL：223 张业务数据表 `TRUNCATE ... RESTART IDENTITY CASCADE`；
- 包括 discovery observations/receipts/current shadow、identity、account sessions/deltas、risk、violation、read models、router assessments、shared observations、inventory、application batches、audit logs、local auth sessions；
- ClickHouse：`proxy_sentinel` 全部业务表 truncate，保留 `schema_migrations`；
- Kafka/Redpanda：删除并重建 `ps.discovery.events.v1`、`ps.identity.events.v1`，6 分区，删除旧 consumer groups；
- Redis：`FLUSHALL`；
- 文件：清空 `/var/lib/proxy-sentinel`、`/opt/proxy-sentinel/data/{device-signals,zeek,stream-journal,eventbus,suricata,staging,audit-cancelled-source,shadow,exports,stream-audit,watchdog}` 和 `/var/log/suricata`。

保留的控制面配置和恢复元数据：

- `local_users`、`schema_migrations`、`sensors`、控制面配置/策略/产品目录/指纹规则；
- `stream_source_cutovers` 的旧代次记录（closed）和新代次 active 记录；
- 应用目录、设备指纹库、迁移与发布目录未删除。

登录会话已清空，登录账号保留；页面需要重新登录。

## 新数据节点

- 清理起始：`2026-10-31T09:14:01Z`（17:14 CST）；
- 新 stream 切流：packet/handshake/DHCP 使用 `*fresh-20261031T092000Z`，discovery 使用 `discovery-fresh-20261031T092000Z`；
- 采集恢复：约 `2026-10-31T09:28Z`（17:28 CST）；
- 两小时窗口：约 17:28–19:28 CST，验收提醒设在 19:32 CST。

## 现场验证

```text
control plane readyz        200
failed proxy-sentinel units 0
discovery current shadow    8,291
发现页当前设备              7,064
ClickHouse normalized       73,846
ClickHouse passive discovery 51,778
Kafka discovery lag         250（初始突发，随后观察）
Redis keys                  0（热态尚未建立）
```

旧业务表关键计数：

```text
account_sessions    0
audit_logs          75（重置后新产生）
local_users         1
```

当前页面已能显示已开启协议 ARP/DHCP/DNS-SD/LLDP/SSDP 和哑终端线索；DNS-SD 首批媒体播放线索已出现。

## 追加严格截断

为消除重启前最后抓包事件时间戳混入新窗口，额外删除：

- `stream_discovery_facts` 中 `observed_at < 2026-10-31T09:20:00Z` 的 429 行；
- `stream_discovery_device_state` 中 `last_seen < 2026-10-31T09:20:00Z` 的 429 行；
- ClickHouse `normalized_events` 中 timestamp 早于 09:20Z 的 3,566 行；
- 删除后 `stream_discovery_facts/state` 最小值均为 09:28:16Z，新窗口内无早于切流点的事件。

## 新窗口 DHCP 运行时

重置后 DHCP 设备已由 R8/eventbus 链路进入发现列表，但 `discovery_protocol_runtime` 的计数曾为 0。current-shadow 现在按活跃 stream facts 同步 DHCP 的 `received/parsed/admitted` 和 `last_seen`；现场已显示约 1,493，且持续更新。

## 新窗口消费刷新

eventbus consumer `--flush-interval` 从 500ms 调到 100ms，降低 ARP 突发下的 group lag；现场 lag 约 250，未出现写入错误。

## 时区修正后的严格清理

ClickHouse `normalized_events.timestamp` 是 Asia/Shanghai 时区，第一次按 UTC 字面量删除只清到了错误边界。已按 `17:28:00 +08:00` 重新清理：

- 删除窗口前 normalized_events 2,617 + 18 行；
- 清理后 normalized_events 最早时间 `2026-10-31 17:28:06 +08:00`；
- `stream_event_search`、`stream_event_body_short`、`stream_event_body_evidence`、`stream_risk_features_v1` 的窗口前记录均为 0；
- PostgreSQL stream facts/state 最早时间保持 `09:28:16Z`。

## 对照终端管理截图补充详情属性

参考用户提供的终端管理截图，发现页设备详情新增：

- 设备类型、制造商、型号；
- MAC、当前地址；
- 网络域、VLAN、采集传感器；
- 首次观测、最近观测、证据数。

截图中的操作系统、接入交换机端口、服务端口（80/139/445/515/9100）来自 SNMP/NDM 和主动服务探测；当前被动发现链路没有这些数据，未伪造展示。

## 对照学校终端管理界面调整发现列表

参考截图增加终端管理风格列：

- 终端类型
- 制造商 / 型号
- 网络位置（网络域、VLAN、采集传感器）
- 发现依据、证据状态、最近观测、操作

后端对缺失制造商按 MAC OUI 补全；现场已出现 `Intel Corporate` 等厂商。

仍未伪造操作系统、接入交换机端口、服务端口和 NDM 事件，因为这些需要 SNMP/NDM 数据源。

## 终端台账列宽调整

发现列表增加操作系统线索列，并压缩列宽，使 1440 视口内操作列完整可见。操作系统仅从主机名前缀推断并标注“线索”，不替代 SNMP/NDM 的确定操作系统。

## 终端类型线索

根据主机名前缀补充办公终端/移动终端/哑终端线索，并在界面标注“线索”；不替代 OUI/SNMP 的确定类型。

## SNMP 候选排序

候选按 `.254` 网关、网络设备厂商、出现次数、空名称加权；主机名像手机/电脑的候选降权。现场首选已变为 `10.202.255.254`，其后是各网段 `.254` 候选。

## 启用被动 SNMP

已把现场发现配置中的 `snmp` 打开并重启 discovery worker：

- SNMP 运行时捕获约 831、解析/处理约 80；
- 发现页“已开启协议”会显示 SNMP；
- 但当前没有 SNMP stream facts/current 设备记录，说明只看到 SNMP 帧，尚未形成可投影终端；
- OS/端口仍需 SNMP 主动轮询或 MIB 数据，不能仅凭当前被动帧补全。
