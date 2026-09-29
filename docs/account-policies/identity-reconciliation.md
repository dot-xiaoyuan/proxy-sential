# 全量身份对账与来源中断监测

## 接入契约

在数据库模式应用 `022_identity_full_snapshots.sql` 后，认证源可向 `POST /api/v1/integrations/identity/snapshots` 提交完整在线清单。使用现有身份集成 Bearer Token；全局只读开关会拒绝提交。令牌持有者代表认证源的在线清单权威，应仅交给受控认证适配程序。

每份快照严格限定 `source + sensor_id + campus_id + access_domain`。增量事件必须使用相同作用域，不能混用不同传感器；已有无传感器标识的策略事实不会被新传感器快照冒认或结束。

必填字段和样例见 [完整快照样例](../../examples/identity/full-snapshot.json) 及 OpenAPI。发送样例前应替换观测时间和实际清单。

- `observed_at` 是上游一致在线视图的时间，不是客户端抓取结束时间。接受过去七天内、不晚于当前时间、最多微秒精度的时间。
- `reconcile_interval_seconds` 是采集端配置的全量对账周期，范围 1–86400 秒。
- `complete=true`、`expected_count` 和 `records` 必须同时明确提供。只有认证系统确认在线总数与完整清单条数一致时才提交；缺字段、null、分页中断、记录格式错误均不能伪装成完整清单。
- 每条记录至少有 `session_id`、`account_id`、合法 `ip`。同一会话/IP 重复会拒绝整份；终端标识、MAC、类别、用户组和产品可选。缺少设备标识仍可确认认证会话，但不虚构可计入硬配额的设备。
- 空清单必须显式使用 `expected_count=0, records=[]`，表示该作用域确认没有在线会话；仅影响同作用域。
- 单次最多 10000 条、请求体最多 16 MiB。**不能将同作用域的完整清单拆成多份 complete 请求**。更大的清单需要后续分片暂存与最终提交协议。
- 记录中的时间、来源、作用域、状态和确认周期不得与快照头冲突。服务端通过身份适配器生成标准事件，并标记 `session_status=reconcile`；原始引用包含快照 ID 及作用域。

认证适配程序应按配置周期获取上游一致快照，确认所有分页属于同一快照且总数一致，再整体提交。当前服务提供接收协议，不主动连接未知认证系统，也没有把普通 Redis SCAN 当成一致在线快照。旧增量桥接程序可以继续工作；真实认证系统的快照采集需按其接口实现并单独验收。

## 提交与重试

`Idempotency-Key` 是作用域内稳定的快照 ID。成功首次返回 202，完全相同的重试返回 200；同 ID 改内容或同作用域同时间换内容返回 409。记录顺序不影响已规范化快照的一致性。对 503、网络超时、响应丢失，保留原始正文和原 key 重试，不用新 key 重发同一时间快照。

PostgreSQL 在一个事务中写入完整快照和 `identity.snapshot.commit` 审计记录，作用域级事务锁串行化并发提交。审计记录的 actor 为 `identity-integration:<source>`。任何一步失败均回滚；不存在“部分记录生效、缺失会话已下线”的中间状态。

快照保留标准事件正文用于策略重放，保存在 PostgreSQL `identity_full_snapshots.document`，不会伪造 ClickHouse 中的原始采集记录，也不会更新旧 `account_sessions` 汇总视图。账号策略消费者统一读取快照及增量事实。独立账号详情页面后续应使用此有效区间路径展示归属，不能把旧汇总表当作新的权威在线清单。

## 时间归责

查询按事件时间合并增量事实和完整快照，保留最近七天快照及窗口前最近一份基线。

- 快照缺失的同作用域会话自快照时刻结束；保留此前有效区间。
- 迟到的快照和增量事实按观测时间重放，不按到达顺序覆盖状态。
- 后续完整快照确认重新在线时可开始新有效区间；普通心跳不能重新激活已结束会话。
- 满三个配置对账周期未刷新，来源变为 interrupted，其未结束会话在该中断时段不能确认账号归属。增量心跳不掩盖全量对账中断。
- 中断状态按证据发生时间判断；来源现在中断不会撤销此前有效的归属，恢复后的新快照也不会填补历史中断区间。
- 同时存在不同账号的冲突仍保守处理；不因快照功能新增自动处罚。

增量身份写入已补齐 `policy_identity_observations`，与原有身份视图在同一 PostgreSQL 事务提交。新生成的身份事件 ID 纳入来源与传感器，防止跨来源去重；已保留的旧标准事件不重写。

## 状态与监测

`GET /api/v1/integrations/identity/status` 保留旧字段，新增 `reconciliation_supported` 和 `sources`，沿用 `integrations:write` 权限。

每个来源作用域返回最后快照 ID、观测/接收时间、配置周期、清单条数、距观测时间的秒数，以及 healthy/interrupted。重试和迟到快照不能刷新最新观测时间。

`/metrics` 增加：

- `proxy_sentinel_identity_reconciliation_available`：数据库状态是否可读。
- `proxy_sentinel_identity_source_interrupted`：各作用域是否中断。
- `proxy_sentinel_identity_snapshot_age_seconds`：距最近完整快照的观测时间。
- `proxy_sentinel_identity_snapshot_sessions`：最近清单的条数，**不是当前已确认在线数量**。

目前仅监测已成功提交至少一份快照的来源。未完成首次接入的来源不会自动出现在列表；来源预注册与首次数据到达告警需后续补齐。此实现以正确性回放为验收基线，尚未做大规模身份清单容量验收；七天高频全量清单的存储及查询成本需要现场规模评估，不能套用应用统计的百万事件性能结果。
