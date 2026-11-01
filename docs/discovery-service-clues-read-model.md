# 服务公告线索短期读模型

`/discovery/service-clues` 为本页最多 50 个传感器/MAC/当前地址读取最近两小时 DNS-SD 服务类型、实例、目标、端口、最近观测时间和证据事件键。`normalized_events` 是权威原文；服务公告不证明端口开放。

## 选型与成本

现场已有 `discovery_service_facts_shadow`（只读核对约 75,869 行、671 MB），但它和 `stream_discovery_facts` 都按事实键保存最新版本。查询旧事实在两小时内被更正或撤销前的公告组，无法只靠当前事实还原。前者还可能与 `normalized_events` 的接纳范围不同。为它增服务列和索引虽省一张表，却不能保持现有接口的事件窗口语义。

ClickHouse 迁移 `062_discovery_service_clues_10m.sql` 从新写入的 `normalized_events` 中只选带 `service_port` 的 DNS-SD，按 10 分钟、传感器、源 IP、源 MAC 和服务字段聚合。表只存这些结构化列、最近观测聚合状态和事件键聚合状态，不复制 payload/raw。主键 `(sensor_id,source_ip,window_start,...)` 服务本页地址和时间裁剪；按小时分区并启用 `ttl_only_drop_parts=1`，四小时 TTL 在整 part 过期后删除，避免日分区内反复重写过期行。正常仅约四至五个小时分区活跃，实际 part 数仍须现场核对。每个源插入块新增匹配分组的聚合写入和索引项；实际增量行数、磁盘字节、写入耗时与 CPU 必须在 184 以持续真实流量记录，不能按理论行数宣称容量收益。无结果版本缓存；事件插入同步更新 MV，时间窗口自然失效。

## 上线与切读

1. 先应用迁移，保持 `PROXY_SENTINEL_DISCOVERY_SERVICE_CLUES_READ_MODEL` 未设置。旧查询仍从 `normalized_events` 读取。迁移账本在 MV 创建成功后才写入，其 `applied_at` 是保守的新输入起点；不回填旧事件。
2. 等账本时间早于固定查询 `since`（正常请求为当前时间减两小时），再用相同的目标集合和固定 `since` 分别运行旧查询、新查询。比较传感器/MAC/IP、服务字段、端口、最近观测和证据键的有序结果，覆盖有公告和无公告的页面；同时间戳多个事件键时，旧查询的 `argMax` 本来无确定并列顺序，应单独核对这些并列。检查 `EXPLAIN indexes=1` 是否利用传感器/IP/桶主键，并在真实冷读、热读中记录 `read_rows`、`read_bytes`、耗时及 HTTP 500。检查 `system.parts` 的活动行数和字节、MV 写入前后的持续输入吞吐与资源。
3. 结果和成本可接受后，在 184 测试环境开启该环境变量并重启控制面。运行时仍按迁移账本时间检查两小时完整覆盖；请求窗口超过三小时自动走旧查询。继续观察真实流量和页面。关闭变量或回退应用可立即恢复旧读取，原始事件及旧读路径未改动。

关闭读开关或回退应用不会停止 MV 的同步 INSERT 成本。若新 MV 导致源 INSERT 异常，或在同等输入下 INSERT P95 持续显著上升且积压增长，先保持读开关关闭，再受控执行 `DETACH TABLE proxy_sentinel.discovery_service_clues_10m_mv PERMANENTLY SYNC`；目标表和原始事件保留。重新 ATTACH 后缺口期的输入不在模型中，原 062 账本时间不能再作为切读覆盖证明，必须另建覆盖门槛并重新比对。操作语义见 ClickHouse [DETACH](https://clickhouse.com/docs/reference/statements/detach) 与 [ATTACH](https://clickhouse.com/docs/reference/statements/attach)。

模型表 TTL 只用于这份短期辅助结果，不改变原始事件、案件证据或归档的保留期。迁移不修改 PostgreSQL；目前没有独立 ClickHouse 集成环境，SQL 引擎执行、写入增长和冷读收益均待现场验证。

迁移前后在 184 以相同的 10 分钟窗口执行以下只读采样；第一条统计 `normalized_events` 同步 INSERT 数量、写入行/字节及耗时，第二条按小时查看模型表活动 part 数、行数和磁盘字节。首次采样需记下 UTC 时间，避免把流量变化当作 MV 成本。

```sh
ssh -o BatchMode=yes root@222.204.3.184 'docker exec -i proxy-sentinel-clickhouse sh -c '\''clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery'\''' <<'SQL'
SELECT count() AS inserts,sum(written_rows) AS source_rows,sum(written_bytes) AS source_bytes,
 quantileExact(0.5)(query_duration_ms) AS insert_p50_ms,
 quantileExact(0.95)(query_duration_ms) AS insert_p95_ms
FROM system.query_log
WHERE event_time>=now()-INTERVAL 10 MINUTE AND type='QueryFinish'
 AND startsWith(query,'INSERT INTO normalized_events');
SELECT partition,count() AS parts,sum(rows) AS rows,sum(bytes_on_disk) AS bytes_on_disk
FROM system.parts
WHERE active=1 AND database='proxy_sentinel' AND table='discovery_service_clues_10m'
GROUP BY partition ORDER BY partition;
SQL
```
