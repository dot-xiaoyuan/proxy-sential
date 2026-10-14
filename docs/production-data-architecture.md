# 生产数据架构

Proxy Sentinel 生产形态不以 JSON 文件作为主存储。文件化 shadow run 只用于本地回放、紧急兜底和导出归档。

设备中心的目标设计见 [设备中心存储与查询设计](device-center-storage-query-design.md)，强制约束见 [AGENTS.md](../AGENTS.md#存储查询与容量约束)。2026-10-13 已落地第一阶段的增量账本、游标读取和新鲜度字段，并按用户授权在 184 以现有数据部署联调。迁移与应用切换已完成，历史回填和逐事件 5 秒时效仍未达标；本轮短时并发结果不代表 10 倍容量验收通过。实际版本、数据规模与结果见 [现场评估记录](../artifacts/device-center-query-20261013/deployment-readiness.md)。

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

- PostgreSQL 存控制面结果：sensor、collector run、evidence、risk snapshot、device signal facts、labels、audit logs、rulesets、decision actions。设备中心目标模型由入库批次账本、持久任务、当前设备状态、检索关系和 30 天热查历史组成；既有 device inventory snapshots 是旧版 IP 库存模型，不再作为所有设备列表的统一设计。
- ClickHouse 存高吞吐数据：normalized events、ingest diagnostics、事件类型统计、事件检索样本和 rollup 分析表；目标模型增加设备相关历史及必要支撑事件的一年归档。
- 原始 EVE 或后续采集后端原始日志只保留短期引用、对象存储或脱敏导出，不作为前端主数据。

职责边界：

- ClickHouse 可以保存标准事件明细、采集诊断明细、按时间/IP/type/domain/fingerprint 预聚合的分析表。
- ClickHouse 不承担设备中心当前列表、当前设备摘要或复核状态查询。原始事件展开和超过热查范围的历史归档走独立路径；设备相关归档查询不自动改变所有流量明细的保留期。
- PostgreSQL 是控制面结果库。当前设备列表读已生成的状态和检索索引，详情首包只读摘要；历史、关联、原始证据独立分页。禁止请求内重建全网地址、聚合全部历史或取回全部设备后在 Go 中分页。
- `/events` 是默认查询 ClickHouse 明细的控制面接口；必须带时间窗口或 from/to，必须有 limit，默认 50，最大 200。
- 活动态势和趋势接口应优先读 ClickHouse rollup；不能把大范围明细拉回 Go 进程实时聚合。

初始 DDL（不是当前全部迁移清单）：

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

设备中心目标写入路径：

```text
Suricata/Zeek/认证/发现来源
  -> Adapter -> NormalizedEvent -> 入库缓冲／持久暂存
  -> 认证来源：PostgreSQL 收件箱先确认并创建设备任务
  -> 文件/发现来源：登记批次后写入 ClickHouse，核对完整性
  -> PostgreSQL 提交批次确认与待处理任务
  -> 增量更新设备状态、检索关系和热历史
  -> 同事务提交消费进度与结果版本
  -> Control Plane API/UI
```

### 可靠写入与状态更新

- 扩展已有入库批次账本及检查点，统一文件、认证和发现采集的确认协议。批次有稳定 ID、记录序号、数量和校验值；源输入或持久暂存保留至可恢复确认完成。
- ClickHouse 成功而 PostgreSQL 未确认时，从持久批次恢复并补交任务。消费按任务状态保留缺口，不只推进最大事件时间或最大序号。
- 业务事实按事件发生时间和来源语义处理，消费与时效按首次入库确认处理。重复、乱序、晚到、更正、撤销和自然过期必须被明确处理，重试不能重置时效起点。
- 常规设备更新只处理受影响的事实与关系，禁止读取该设备全部历史再删除重建投影。重复 renew 更新确认时间、有效期与经幂等校验的必要计数；不能依赖 ClickHouse 后台合并完成才保证去重。
- 沿用 `device_signal_facts` 等可用事实层，但不能把单次 shadow run 内生成全部结果的旧流程作为实时处理前提。完整回填、规则重算、修复与统计分别限制资源，实时任务优先。
- 结果与处理进度同事务提交。使用结果版本、租约校验和受控重试处理崩溃恢复，不以跳过积压或将未处理任务标记完成维持表面健康。
- 大型认证快照分块处理；租约、会话和公告由到期调度器更新，即使没有新事件也不能保留过期的当前状态。

### 查询与时效

- 终端、网络设备、哑终端和发现线索列表读取状态投影，在数据库中筛选、排序、取一页后，才为页内设备补充有限摘要。
- 当前有效地址、最后观测地址、历史地址分别表达；服务线索、低置信证据和冲突保留其来源与不确定性，不为优化性能改变业务语义。
- IP/MAC/账号使用精确检索；名称及综合文本使用专用索引，少于三个 Unicode 字符按前缀查询，三个及以上字符支持包含检索。当前和历史命中返回匹配来源。
- 列表采用绑定筛选、排序和版本的不透明游标，不使用深 `OFFSET` 或强制精确总数。常用分类计数增量维护，复杂总数独立计算并返回统计时间；固定结果导出走独立快照任务。
- 详情首包返回当前摘要，关联、历史、证据分别按范围分页；超过 30 天的跨设备追溯进入独立归档查询任务。
- 设备中心相关标准事件首次成功入库后 5 秒内应通过 API 反映其处理结果；当前状态接口另按 P95 ≤500 毫秒、P99 ≤1 秒验收。缓存按结果版本失效，不得遮蔽已提交变化；旧缓存兜底明确标记，不计为达标。
- 新鲜度包括入库水位、处理水位、最老待处理时间、延迟、结果版本和处理状态，以未完成缺口计算，不能只展示最近一次任务成功。
- 查询失败、无记录、处理中和过期结果明确区分；旧分页参数须显式迁移，不静默回退全量扫描。后续实现同步更新 OpenAPI、前端、后端与 mock。

### 旧版 IP 库存模型的边界

`device_inventory_snapshots` 按 `run_id + window + ip` 保存的库存快照，以及 `/devices`、`/ips/{ip}/devices` 的旧版 IP 画像规则属于兼容路径。原有 `confidence >= 0.80`、`include_weak` 等过滤语义不能直接套到以设备身份为单位的设备中心，也不能将 IP 库存快照等同于当前地址权威状态。

重构须在影子比较后切换相关读取路径，不能仅改文档便声称旧接口已迁移。原始事件样本仍通过 `/events` 独立分页展开，风险评分与策略闭环不直接依赖采集后端原始字段。

## 历史生命周期与容量验收

- 设备身份、地址变化、发现证据及必要标准事件按首次入库时间热查 30 天，归档保留至入库后一年；另存事件发生时间以支持晚到事实。当前状态不随历史分区到期消失。
- 归档数量、标识与校验核对完成前不清理唯一副本；案件证据独立保护。归档失败保留原数据并报告容量风险，清理吞吐必须跟得上过期数据增长。
- 验收分别覆盖 1 倍、3 倍、10 倍设备数、历史量、持续写入速率及组合增长。10 倍组合负载在隔离环境持续 24 小时，保持 20 路并发查询，包含冷缓存、重启、规则重算和归档清理。
- 每条测试事件从首次入库确认到 API 可见超过 5 秒都记为违约；不以平均值或分位数掩盖超限。记录查询计划、扫描量、队列年龄、吞吐、WAL、I/O、内存及归档增长。
- 数据库配额可按压测调整，容量承诺必须附硬件、配置、数据分布和负载结果；资源不足时报告缺口，不缩短保留、不跳任务、不宣称达标。

## 迁移策略

数据库运行模式使用 `--storage-mode db`，PostgreSQL 与 ClickHouse 是运行时存储；JSON 文件模式只允许显式用于开发测试。历史文档中的 30 节点不是本次现场发布目标，现场目标与授权以 AGENTS.md 为准。

生产目标：

```text
--storage-mode db
--postgres-dsn ...
--clickhouse-dsn http://clickhouse:8123/?database=proxy_sentinel
```

`db` 模式要求 PostgreSQL 和 ClickHouse DSN 同时配置。PostgreSQL 使用 pgx/sql，
ClickHouse 使用 HTTP interface，因此 `--clickhouse-dsn` 应提供 `http(s)` URL。
`dual` 模式的文件兼容行为属于历史过渡路径，不能作为设备中心可靠入库和 5 秒时效设计的替代。

后续重构使用新增、可并行验证的结果表与账本扩展，不改写已应用迁移，也不直接部署本地未发布投影。先持续接收实时变化，再分批回填并进行影子比较；通过幂等与版本控制合并，验证当前地址、分类、冲突和历史匹配后切换读取。保留旧读取开关和应用回退入口，数据库迁移向前兼容。

旧索引、旧表及历史数据退役在归档核验、依赖检查和容量验收后独立进行。本文不授权执行迁移、清理或发布；现场部署仍需单独授权并遵守 AGENTS.md。
