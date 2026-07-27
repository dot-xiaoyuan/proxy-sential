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

- PostgreSQL 存业务状态：sensor、collector run、evidence、risk snapshot、labels、audit logs、rulesets、decision actions。
- ClickHouse 存高吞吐数据：normalized events、ingest diagnostics、事件类型统计、IP 事件特征。
- 原始 EVE 或后续采集后端原始日志只保留短期引用、对象存储或脱敏导出，不作为前端主数据。

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

## 迁移策略

当前 30 机器使用 `--storage-mode dual`，继续保留文件输出，同时让 API 和前端按生产数据对象组织。

生产目标：

```text
--storage-mode db
--postgres-dsn ...
--clickhouse-dsn http://clickhouse:8123/?database=proxy_sentinel
```

`db` 模式要求 PostgreSQL 和 ClickHouse DSN 同时配置。PostgreSQL 使用 pgx/sql，
ClickHouse 使用 HTTP interface，因此 `--clickhouse-dsn` 应提供 `http(s)` URL。
`dual` 模式在 DSN 完整时同步写 DB；未配置 DSN 时保留当前文件化路径，适合 30 机器平滑过渡。
