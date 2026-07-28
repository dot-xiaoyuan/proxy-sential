# 开发 Backlog

## Sprint 1: Suricata Adapter

目标：把 Suricata EVE JSON 转换为标准事件。

任务：

- 建立 CLI 项目骨架。
- 实现 `adapter suricata --input --output`。
- 支持 flow、dns、tls、http 事件。
- 输出 JSONL。
- 增加 malformed line 容错。
- 增加 fixture 回放测试。

验收：

- 输入 EVE JSON，输出符合 `schemas/normalized-event-v1.schema.json` 的事件。
- 每条事件都有 subject.ip。
- 原始来源可追溯到 raw_ref。

## Sprint 2: Replay and Window Store

目标：建立可回放的证据计算基础。

当前进展：

- 已实现 `replay --input [--output]`。
- 已支持按 `subject.ip` 聚合 1m、5m、10m、1h 窗口。
- 已支持事件去重、malformed line 容错和基础统计输出。

任务：

- 实现 `replay --input`。
- 实现按 IP 的滑动窗口。
- 支持 1m、5m、10m、1h 窗口。
- 实现事件去重。
- 输出每个 IP 的基础统计。

验收：

- 固定 fixture 多次回放结果一致。
- 能查看某个 IP 的窗口内事件数量、域名基数、UA 基数、JA3 基数。

## Sprint 3: First Evidence Rules

目标：实现第一批有效证据。

当前进展：

- 已实现 `evidence --input [--output] [--window]`。
- 已实现 `multi_user_agent`、`multi_ja3_ja4`、`domain_diversity`、`port_distribution`。
- `ttl_clusters` 暂缓：当前标准事件和 Suricata adapter 还没有 TTL 字段，不能在证据层伪造该信号。

任务：

- `multi_user_agent`
- `multi_ja3_ja4`
- `domain_diversity`
- `port_distribution`
- `ttl_clusters`

验收：

- 每条证据包含 score、confidence、reason、samples。
- 单元测试覆盖正常样本和代理样本。

## Sprint 4: Risk Snapshot CLI

目标：能输出 IP 风险结果。

当前进展：

- 已实现 `risk inspect --input evidence.json --ip <ip>`。
- 已实现风险分、等级、置信度、证据 ID、summary 和影子 recommended_action。
- 弱证据 `domain_diversity`、`port_distribution` 单独或组合不会进入 confirmed。

任务：

- 实现风险评分器。
- 实现等级判定。
- 实现 `risk inspect --ip`。
- 输出 summary 和 recommended_action。
- 支持规则配置文件。

验收：

- 一个 IP 的风险结果可解释。
- 多证据能组合加权。
- 单弱信号不会进入 confirmed。

## Sprint 5: Storage and API

目标：让结果可查询。

任务：

- 选型并接入 PostgreSQL 或 ClickHouse。
- 保存 normalized events、evidence、risk snapshots。
- 实现基础 HTTP API。
- 支持 labels 标注。

验收：

- 能查询高风险 IP 列表。
- 能查询 IP 证据时间线。
- 能标注误报和确认代理。

## Sprint 6: Shadow Mode

目标：真实流量旁路观察。

任务：

- 接入真实 Suricata EVE 输出。
- 运行 7 天影子模式。
- 每日导出高风险样本。
- 统计误报来源。

验收：

- 输出影子模式评估报告。
- 明确下一轮要调整的规则和负证据。

## Sprint 7: Decision Integration

目标：接入策略动作但默认不处罚。

任务：

- 实现 allowlist。
- 实现 cooldown。
- 实现 audit log。
- 实现 shadow action。
- 预留降速、踢线、通知接口。

验收：

- 所有动作可追溯。
- 可按用户组灰度。
- 支持手工撤销。

## Sprint 8: MVP Review

目标：评审是否进入 AF_XDP/Rust PoC。

任务：

- 汇总性能数据。
- 汇总误报和漏报。
- 汇总有效证据排名。
- 对比 Suricata 能力和业务需求差距。

验收：

- 输出继续 Suricata、混合 sensor、全自研 sensor 三选一建议。

## Sprint 9: Event Search and Standard Event Detail

目标：把 ClickHouse 中的标准事件变成可查询、可钻取、可复盘的数据资产。

任务：

- 扩展 `GET /api/v1/events`，支持 `from/to/window/sensor_id/src_ip/dst_ip/domain/user_agent/port/proto/type/limit/cursor`。
- 查询源使用 ClickHouse `normalized_events`，返回标准事件字段和分页元信息。
- 增加 `GET /api/v1/events/{event_id}` 的详情联动，不暴露 Suricata 原始 EVE。
- 前端新增 `/events` 页面，支持筛选、分页、事件详情抽屉。
- IP 详情页的事件样本提供跳转，能查看完整上下文。

验收：

- 10m、1h、24h 和自定义时间范围的事件数不同且符合 ClickHouse 结果。
- 能按源 IP、目的 IP、域名、User-Agent、端口、协议、事件类型筛选。
- IPv4、IPv6、长域名、长 UA 不破坏 API 和页面布局。
- API 只返回 NormalizedEvent 字段，不返回采集器原始结构。

## Sprint 10: Access Object Drilldown

目标：让“访问了什么”和“哪些风险 IP 关联这些访问对象”可解释、可下钻。

任务：

- 新增访问对象查询能力，覆盖 domain、dst_ip、user_agent、ja3、ja4。
- `/activity` Top domains、目的 IP、User-Agent、JA3/JA4 可跳转到事件检索视图。
- 前端新增访问对象详情视图，展示关联 IP、事件趋势、风险 IP 分布和样本事件。
- 支持从风险 IP 反向查看其 Top 访问对象和同类访问者。

验收：

- 能从一个域名看到关联源 IP、风险等级分布、最近事件样本。
- 能从一个 UA 或 TLS 指纹看到关联 IP 和 Top 目的对象。
- 所有钻取仍只使用标准事件、证据和风险快照。

## Sprint 11: Review Loop and Label Persistence

目标：把人工复核从前端占位变成可审计、可回流风险判断的闭环。

任务：

- `POST /api/v1/labels` 支持可配置启用，默认生产仍可保持 read-only。
- labels 写入 PostgreSQL，并同步写入 audit logs。
- 风险 IP 增加复核状态：未复核、确认代理、误报、良性、需要更多数据。
- 风险评分读取 labels 作为人工结论和负证据输入，但不自动处罚。
- 前端 `/review` 和 IP 详情页展示复核状态、历史标注和审计结果。

验收：

- 标注必须包含原因、操作者、时间和目标对象。
- read-only 模式继续返回 403 且不下发 mutating 权限。
- 复核状态能影响后续展示，不改变影子模式安全边界。

## Sprint 12: Risk Rule Governance and Negative Evidence

目标：降低误报，让风险判断可配置、可解释、可复盘。

任务：

- 增加 rulesets 版本管理和规则配置展示。
- 引入负证据：白名单、测试设备、已知下载器、游戏、办公软件、加速器特征。
- 增加多窗口风险对比：1m、10m、1h、24h。
- 风险摘要展示规则版本、证据权重和负证据命中情况。

验收：

- 同一 IP 能看到当前风险、历史趋势和规则版本。
- 弱证据仍不能单独进入 confirmed。
- 误报样本能通过 labels 和负证据进入下一轮评分。

## Sprint 13: Realtime Ingest Worker

目标：把标准事件入库从 10 分钟 batch 推进为接近实时的常驻 ingest。

任务：

- 新增 `proxy-sentinel ingest run`，持续 tail EVE 并维护 offset。
- 标准事件和采集诊断实时写 ClickHouse。
- 风险评分继续按窗口批处理，避免在热路径做复杂聚合。
- 保留当前 `proxy-sentinel-shadow.timer` 作为兜底和回放路径。

验收：

- EVE 增长后，ClickHouse `normalized_events` 在秒级到分钟级可见新增事件。
- 支持日志轮转、截断、重复事件、malformed line。
- ingest worker 异常退出后可从上次 offset 恢复。

## Sprint 14: Multi Sensor and Production Hardening

目标：支撑多测试环境和后续生产部署，不把单机 30 作为产品形态。

任务：

- 增加 sensors 管理、sensor 健康状态和多 sensor 查询。
- 标准化 systemd / docker compose 部署文档。
- 增加 ClickHouse TTL、分区、物化视图和 PostgreSQL 备份策略。
- 增加 API 认证鉴权、HTTPS / 反向代理、监控告警和自检接口。
- 前端明确测试环境、生产环境和当前 sensor，不使用“办公室”作为产品概念。

验收：

- 多 sensor 数据可按 sensor_id 隔离查询。
- 服务异常、数据延迟、采集停止能在控制面明确提示。
- 生产部署有恢复、备份和容量规划文档。
