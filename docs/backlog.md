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

