# AI API 中转站使用识别

## 目标

回答“哪些内网 IP 在使用 AI API 中转站（AI 中轉站）”。

中转站是位于调用方与官方大模型 API 之间的转发端点：调用方把 `base_url` 指向第三方域名，用第三方签发的 key 调用 OpenAI / Anthropic / Gemini 等模型。因此**识别中转站使用不需要解密流量**：客户端与中转站建立 TLS 连接时，ClientHello 里的 SNI 是明文的；同时 DNS 查询和明文 HTTP Host 也可观测。

## 判定与数据来源

判定链路完全建立在标准事件之上，采集层不新增字段：

1. 采集后端产出 `dns` / `tls` / `quic` / `http` 标准事件，携带 `payload.query`、`payload.sni`、`payload.host`。
2. 证据层把这四个观测值（另含 `server_name`）交给指标匹配器 `internal/airelay`。
3. 命中指标即产出证据 `ai_relay_domain_usage`，按源 IP 聚合，规则返回分数、置信度、窗口、解释文本和命中样本。

匹配只在**完整标签边界**上进行：`api.yunwu.ai` 命中 `yunwu.ai`，`notyunwu.ai` 和 `yunwu.ai.evil.example` 都不命中。资产里显式声明的官方厂商域名（`api.openai.com`、`api.anthropic.com` 等）先于指标排除，保证中转站指标永远不会遮蔽官方端点。

## 指标资产

- 位置：`internal/airelay/data/indicators.json`，通过 `//go:embed` 编译进二进制，包初始化时校验，非法资产直接构建失败。
- schema：`ai-relay-indicators/v1`，字段为 `schema_version`、`version`、`updated_at`、`sources`、`official_domains`、`indicators`。
- 单条指标：`domain`、`match_type`（`exact` / `subdomain`）、`category`（`relay` / `aggregator`）、`name`、`confidence`、`status`、`source`、`note`。
- `source` 必须引用 `sources` 中的条目，确保每条指标可追溯到公开来源。
- `status` 只记录本机 DNS 解析核验结果（`resolved` / `unresolved`）。它不代表服务可用、合规或仍在运营；本机网络受限时国内站点也会显示 `unresolved`。
- 校验规则：未知字段、未知来源、非法 `match_type`/`category`/`status`、置信度超出 `(0, 0.90]`、重复指标、与官方域名冲突，全部拒绝加载。

维护方式：更新资产后重新构建。运行时热更新指标集不是本次范围。

来源包括 [awesome-ai-api-proxy](https://github.com/howardpen9/awesome-ai-api-proxy)（中轉站/閘道目录）、[awesome-ai-proxy](https://github.com/mn-api/awesome-ai-proxy)（已停更的历史清单），以及若干运营方官网与 [chatanywhere/GPT_API_free](https://github.com/chatanywhere/GPT_API_free)。

## 证据语义与风控边界

证据类型：`ai_relay_domain_usage`。

- 分数：`26 + 4 × 命中条目数`，上限 42。
- 置信度：取命中指标的最高置信度，上限 0.85。
- 解释文本明确说明“仅证明访问了中转站域名”，不推断实际调用行为。
- 该类型在 `internal/risk` 中被归类为**弱证据**（`isWeakEvidence`），单独命中不会把风险级别推到 high/confirmed，也不会产生自动化处置资格。

这是刻意的保守设计：域名会更换、会重用、会被共享 CDN 承载，域名命中只是线索，必须结合账号和人工复核。项目既有的影子模式与人工撤销约束不变。

## 运行与查询

回放验证（离线、不发送流量）：

```bash
go test ./internal/airelay/ ./internal/evidence/ ./internal/risk/
```

`examples/replay/ai-relay-usage.jsonl` 覆盖命中、官方域名和两类仿冒域名。

真实流量下，指标匹配随常规证据流程运行，无需额外参数。查询使用方清单时按域名或目的地址过滤标准事件：

```
GET /api/v1/events?domain=yunwu.ai
GET /api/v1/events?dst_ip=<中转站解析地址>
```

事件里的 `subject_ip` 即使用方，再按事件时间关联认证会话得到账号。

## 局限

- 指标是开放集合，未入库的中转站查不出来；资产更新是主要运维成本。
- 命中只说明访问了该域名的 443/80，**不能证明**发生了模型调用：浏览器打开中转站控制台、站点静态资源同样会命中。
- 中转站普遍使用 Cloudflare 等共享 CDN，按 `dst_ip` 反查会把大量无关流量算进来；以域名（SNI/DNS/Host）为准。
- NAT/CGNAT 会破坏源 IP 归属，fan-in 计数必须结合身份会话，不能只看源地址数量。
- 加密载荷不可见，无法从流量确认调用了哪个模型、用了哪把 key。
- 本文只覆盖“谁在用中转站”。中转站在校园网中的违规定性与处置策略不在本次范围。
