# 事件总线旧表退役清单

状态：核心读路径已切换；旧表仍保留回退和未迁移功能，不能直接 DROP。

## 旧表清单

| 表 | 现场大小 | 当前用途 | 退役阻塞 |
| --- | --- | --- | --- |
| `account_sessions` | 5.3 GB | 旧身份读回退、风险/运营/共享行为、会话历史 | 身份影子未命中回退；多个运营查询仍读 |
| `identity_ip_mac_history` | 8.5 GB | 旧身份 profile 的 IP 历史、风险关联 | 影子 profile 只派生最近窗口；风险/运营仍用 |
| `identity_access_history` | 877 MB | 旧身份 profile 的接入历史 | 同上 |
| `discovery_observation_latest` | 640 MB | 旧发现 Indexed 回退路径 | 新控制面 flag=false 时回退 |
| `stream_discovery_device_state` | 1.2 GB | 旧 stream projection、freshness、回填 | 发现回退和旧流式查询仍用 |
| `stream_discovery_receipts` | 分区表，月分区合计 16 GB 级 | 识别覆盖输入、旧收据查询 | 识别分钟服务仍从收据聚合，不能退役 |

## 已退役/禁用

- 旧控制面 `proxy-sentinel-control-plane.service`：inactive/disabled；
- 旧识别物化 `proxy-sentinel-recognition-materializer.service`：inactive/disabled；
- 旧 Kafka smoke topic：已删除；
- 无成员旧 consumer group：已删除。

## 退役前置条件

1. 身份读不再回退旧 `account_sessions`，至少 shadow 命中率覆盖验收范围；
2. 风险/运营/共享行为查询迁出新 IP/access 历史表；
3. 识别分钟服务改为从事件总线或 ClickHouse 聚合，不再扫描 `stream_discovery_receipts`；
4. 发现回退窗口结束，旧控制面不再需要启动；
5. 完成只读审计、备份和回滚确认后再 DROP/归档。

## 生产化遗留

- 单节点 Redpanda，RF=1；
- 单块 HDD，无 SSD/NVMe；
- 未启用 TLS/SASL；
- 未做多 broker 故障切换和容量验收；
- 旧表约 16 GB 级历史保留在 184。

这些是生产资源/清理工作，不是当前页面功能缺失；不能在未授权情况下直接删旧表或改生产网络。

## 2026-10-30 范围决定

用户确认：

1. **保留旧表，只完成功能**：不删除 `account_sessions`、identity 历史、旧发现表、`stream_discovery_receipts`；旧表继续承担回退、风险/运营关联和识别输入。
2. **生产化按当前单节点测试范围验收**：不在 184 现有 HDD 上伪做多 broker、SSD 或容量结论；TLS/SASL、多 broker、SSD 验收另立生产化任务。

因此本次“所有功能完成”的验收边界是：

- 所有主页面路由可打开且无崩溃；
- 发现/身份/识别覆盖/活动统计读路径正常；
- 系统健康组件 ready；
- 活跃 Kafka group 无消息积压；
- 旧表和生产化资源不作为本次功能阻塞。
