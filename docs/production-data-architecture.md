# 生产数据架构

Proxy Sentinel 生产形态不以 JSON 文件作为主存储。文件化 shadow run 只用于本地回放、紧急兜底和导出归档。

## 数据分层

```text
Collector Raw Output
  -> Adapter
  -> NormalizedEvent
  -> IngestDiagnostic
  -> Evidence
  -> RiskSnapshot
  -> Decision/Audit
  -> Control Plane API/UI
```

## 存储职责

- PostgreSQL 存控制面结果：sensor、collector run、evidence、risk snapshot、device signal facts、device inventory snapshots、labels、audit logs、rulesets、decision actions。
- ClickHouse 存高吞吐数据：normalized events、ingest diagnostics、事件类型统计、事件检索样本和后续 rollup 分析表。
- 原始 EVE 或后续采集后端原始日志只保留短期引用、对象存储或脱敏导出，不作为前端主数据。

职责边界：

- ClickHouse 可以保存标准事件明细、采集诊断明细、按时间/IP/type/domain/fingerprint 预聚合的分析表。
- ClickHouse 不承担 `/devices` 设备列表、`/ips/{ip}/devices` 设备详情、风险列表设备摘要、证据列表和复核状态这类“当前状态”查询。
- PostgreSQL 是控制面结果库。所有需要稳定分页、复核、解释、当前画像的接口都读 PostgreSQL 结果表。
- `/events` 是默认查询 ClickHouse 明细的控制面接口；必须带时间窗口或 from/to，必须有 limit，默认 50，最大 200。
- 活动态势和趋势接口应优先读 ClickHouse rollup；不能把大范围明细拉回 Go 进程实时聚合。

DDL：

- `migrations/postgres/001_production_schema.sql`
- `migrations/clickhouse/001_production_schema.sql`

## 采集诊断模型

`IngestDiagnostic` 是兼容 Suricata、Zeek、AF_XDP、DPDK 的诊断对象。它描述采集、解析、标准化、证据和风险各阶段的状态，不暴露采集后端原始结构。

schema：

- `schemas/ingest-diagnostic-v1.schema.json`

控制面接口：

- `GET /api/v1/ingest/status`
- `GET /api/v1/ingest/runs`
- `GET /api/v1/ingest/diagnostics`
- `GET /api/v1/ingest/event-types`
- `GET /api/v1/ingest/errors`
- `GET /api/v1/events`
- `GET /api/v1/events/{event_id}`

## 设备识别数据流

Zeek 在生产上保持日志型传感器定位，不直接写数据库，也不负责去重、限流或设备状态维护。

```text
Suricata/Zeek logs
  -> Adapter
  -> NormalizedEvent
  -> ClickHouse normalized_events
  -> Evidence/Risk/Device Inventory builders
  -> PostgreSQL result tables
  -> Control Plane API/UI
```

写入规范：

- shadow run 先把本轮标准事件写入 ClickHouse `normalized_events`，用于审计、回放和事件检索。
- evidence、risk、device inventory 在同一 run 内生成并写入 PostgreSQL。
- `device_signal_facts` 按 `sensor_id + signal_id` 保存去重后的设备信号事实，并用 `device_signal_events` 对 `event_id` 做幂等累计。
- Zeek DHCP/software 的重复 renew 或重复观测不要求 Zeek 限制；Proxy Sentinel 只在事实层增加 `seen_count` 和 `event_ids_sample`。
- `device_inventory_snapshots` 按 `run_id + window + ip` 保存设备库存快照，`/devices` 和 `/ips/{ip}/devices` 默认读取最新快照，不扫描 ClickHouse 明细。

查询规范：

- `/devices` 默认返回 `confidence >= 0.80` 且非 weak-only 的高置信设备画像；`include_weak=true` 才返回只有 UA/TLS/TCP 弱或中信号的 IP。
- `/ips/{ip}/devices` 返回聚合信号 facts 和库存快照，不返回重复 DHCP/software 原始事件。
- 原始事件样本通过 `/events` 单独分页查询，默认折叠在设备详情之外。

## 迁移策略

30 机器生产服务使用 `--storage-mode db`，PostgreSQL 与 ClickHouse 是唯一运行时事实源；JSON 文件模式只允许显式用于开发测试。

生产目标：

```text
--storage-mode db
--postgres-dsn ...
--clickhouse-dsn http://clickhouse:8123/?database=proxy_sentinel
```

`db` 模式要求 PostgreSQL 和 ClickHouse DSN 同时配置。PostgreSQL 使用 pgx/sql，
ClickHouse 使用 HTTP interface，因此 `--clickhouse-dsn` 应提供 `http(s)` URL。
`dual` 模式在 DSN 完整时同步写 DB；未配置 DSN 时保留当前文件化路径，适合 30 机器平滑过渡。
