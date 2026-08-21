# 近期任务计划与每日进度

更新时间：2026-08-21

## 状态说明

| 状态 | 含义 |
| --- | --- |
| 已完成 | 代码、测试或文档已经落地并通过基础验证 |
| 进行中 | 当前优先推进，允许继续拆小任务 |
| 部分完成 | 可交付子项已落地，但仍依赖外部数据、现场环境或后续任务完成闭环 |
| 待开始 | 已明确任务边界，但尚未实施 |
| 阻塞 | 需要外部数据、环境、人工验证或产品决策 |

## 近期总目标

| 阶段 | 时间 | 目标 | 当前状态 | 验收标准 |
| --- | --- | --- | --- | --- |
| P0 身份关联底座 | 2026-07-29 至 2026-07-31 | 打通账号、终端、IP、接入位置标准事件与账号级证据 | 已完成 | identity 事件可回放；账号级风险可生成；基础设施不计入终端并发；控制面可查账号/终端身份 profile |
| P1 设备发现闭环 | 2026-08-01 至 2026-08-05 | 从 IP 设备画像推进到 endpoint 设备登记视图 | 部分完成 | 代码、严格验收报告和 82 个现场 endpoint 候选已具备；仍需人工确认 30-50 台真实设备标准答案 |
| P2 人工复核闭环 | 2026-08-06 至 2026-08-08 | labels 落库、审计、风险展示回流 | 已完成 | 非只读模式可写标注；审计可查；后续风险展示可读取复核状态 |
| P3 翻墙监测 MVP | 2026-08-09 至 2026-08-13 | 接入 Suricata alert/quic 与账号/设备关联 | 已完成 | 账号、设备、目的 IP/域名、规则命中、近 7 天统计可形成复核视图 |
| P4 影子评估 | 2026-08-14 至 2026-08-20 | 连续影子运行并人工抽样复核 | 部分完成 | 现场已连续运行 8 天且采集质量通过；评估/抽样工具已完成，尚缺每日人工复核标签 |

## 每日任务表

| 日期 | 当日目标 | 任务 | 状态 | 产出/备注 |
| --- | --- | --- | --- | --- |
| 2026-07-29 | 完成身份关联第一批代码底座 | 新增 `identity` adapter，支持 RADIUS/Portal 类 JSONL/CSV 转标准事件 | 已完成 | `proxy-sentinel adapter identity` 已接入 |
| 2026-07-29 | 完成 Suricata 翻墙信号入口 | Suricata adapter 支持 `alert` 和 `quic` 标准事件 | 已完成 | 已加单元测试 |
| 2026-07-29 | 完成账号级风险雏形 | 增加账号多 MAC、多接入位置、认证/观测 MAC 不一致证据 | 已完成 | 账号共享 fixture 可生成 account risk |
| 2026-07-29 | 修正基础设施污染 | `gateway/server/infrastructure/network_device/nat` 不计入普通 endpoint 并发 | 已完成 | 基础设施 fixture 不产生共享证据 |
| 2026-07-29 | 打通人工复核写入 | 非只读控制面支持 `POST /labels`，写入审计 | 已完成 | read-only 仍返回 403 |
| 2026-07-30 | 建立身份历史落库 | 从 `identity` 标准事件生成 endpoint、account session、IP-MAC、access history 写入 | 已完成 | `WriteDeviceState` 已写入 `endpoint_entities`、`infrastructure_entities`、`account_sessions`、`identity_ip_mac_history`、`identity_access_history` |
| 2026-07-30 | 增加身份回放测试 | 回放动态 IP、同账号多 MAC、认证 MAC 不一致、基础设施排除 | 已完成 | 已覆盖动态 IP 不拆终端、同账号多 MAC、认证/观测 MAC 不一致、基础设施排除 |
| 2026-07-31 | 接入控制面查询 | 增加账号/终端维度查询接口雏形 | 已完成 | 新增 `GET /accounts/{account_id}/identity`、`GET /endpoints/{endpoint_id}/identity`，可查账号当前关联终端、IP、接入位置 |
| 2026-08-01 | 设备登记模型设计落地 | 定义 endpoint 主表、登记状态、责任人、合并/拆分字段 | 已完成 | `endpoint_entities` 增加登记/责任人/合并拆分字段，新增 `POST /endpoints/{endpoint_id}/registration` 并写审计 |
| 2026-08-02 | 设备列表改造 | `/devices` 从 IP inventory 逐步迁移到 endpoint inventory | 已完成 | `/devices` 返回 endpoint 登记视图，保留 `/ips/{ip}/devices` 兼容 IP inventory |
| 2026-08-03 | 设备详情页改造 | 展示 endpoint 的 IP 历史、账号历史、接入历史、设备信号 | 已完成 | 新增 `/devices/{endpoint_id}` 详情页，页面围绕 endpoint 展示登记、账号会话、IP 历史、接入历史和设备信号 |
| 2026-08-04 | 人工已知设备样本 | 建立 30-50 台人工验证清单模板 | 部分完成 | 已新增模板、字段说明、严格覆盖校验；现场已从近 7 天 DHCP 标准事件回填 82 个设备候选，责任人和真实类型仍需人工确认 |
| 2026-08-05 | 设备发现验收 | 用人工样本验证漏发现、误合并、重复创建、基础设施排除 | 部分完成 | `--strict` 报告已覆盖发现率、误合并、重复创建和基础设施污染；正式结论依赖人工标准答案 |
| 2026-08-06 | 复核状态回流 | 风险列表/IP/账号详情展示 confirmed/false_positive/benign/needs_more_data | 已完成 | risk snapshot 已附加 `review_status`、复核原因、人员和时间；风险列表、复核队列、IP 详情已展示；后端支持 subject/account/endpoint label 合并；不改变评分和处罚 |
| 2026-08-07 | 负证据第一版 | 白名单、测试设备、基础设施、下载器/系统服务降权 | 已完成 | labels 可转为 `negative_evidence`，保留 raw score/level；误报、良性、样本不足会降权或封顶；低置信加密行为不能进入 confirmed |
| 2026-08-08 | 复核审计验收 | 标注必须包含操作者、时间、原因、目标、证据 ID | 已完成 | `POST /labels` 强制携带 `evidence_ids`，空证据标注返回 400 且不写审计；前端无证据时禁用复核表单 |
| 2026-08-09 | 翻墙证据模型 | 定义高/中/低置信翻墙证据类型和输出字段 | 已完成 | 新增 `vpn_proxy_rule_match`、`vpn_proxy_domain_hint`、`encrypted_tunnel_behavior`；Suricata alert 为高置信，QUIC/UDP 443 只作低置信弱证据 |
| 2026-08-10 | Suricata alert 规则接入 | 解析 signature、category、severity、action、metadata | 已完成 | adapter 已支持 `alert/quic`；证据层已从 `signature/category/metadata` 生成翻墙规则命中证据 |
| 2026-08-11 | QUIC/TLS 行为聚合 | 账号/设备维度聚合 SNI、JA3/JA4、QUIC、目的 IP | 已完成 | 新增 `GET /proxy-reviews`，文件模式跨 7 天 run 去重聚合，数据库模式按标准事件 7 天窗口查询；输出账号、endpoint、接入位置、目的对象、协议、持续时间和风险复核状态 |
| 2026-08-12 | 翻墙复核视图 | 展示账号、设备、接入位置、目的对象、规则命中、持续时间 | 已完成 | 人工复核页已接入 `/proxy-reviews`；高/中/低置信分层展示，无标准证据时禁用复核；仍只写 labels 和审计，不触发处罚 |
| 2026-08-13 | 翻墙 MVP 回放测试 | 构造明确代理命中、普通视频会议、低置信长连接 fixture | 已完成 | `examples/replay/` 已覆盖明确 OpenVPN 命中、视频会议 QUIC、6 小时 UDP/443 长连接；后两类保持 normal/record |
| 2026-08-14 至 2026-08-20 | 影子评估 | 每天抽样复核 high/confirmed/suspicious/normal | 部分完成 | 现场已连续运行 8 天；自动评估和每日分级抽样已落地，当前 0 条人工标签，需运营复核后形成准确率与误报 Top 10 |

## 当前已完成验证

| 验证项 | 命令/方式 | 状态 |
| --- | --- | --- |
| Go 单元测试 | `go test ./...` | 已通过 |
| 前端类型检查 | `pnpm typecheck` | 已通过 |
| 账号共享回放 | `examples/identity-account-sharing.jsonl` -> evidence -> risk | 已通过 |
| 基础设施排除回放 | `examples/identity-infrastructure-not-endpoint.jsonl` -> evidence | 已通过 |
| 身份历史构建测试 | `internal/store/identity_test.go` | 已通过 |
| 认证/观测 MAC 不一致测试 | `internal/evidence/evidence_test.go` | 已通过 |
| 控制面身份查询 | `internal/controlplane/server_test.go` | 已通过 |
| endpoint 设备登记 | `POST /endpoints/{endpoint_id}/registration` + `GET /endpoints/{endpoint_id}/identity` | 已通过 |
| endpoint 设备列表 | `GET /devices` | 已通过 |
| 设备页 UI 审查 | 390x844、1280x800、1440x900 Playwright 探针 | 已通过 |
| endpoint 详情页 UI 审查 | 390x844、1280x800、1440x900 Playwright 探针 | 已通过 |
| 人工已知设备模板校验 | `go run ./cmd/proxy-sentinel validate known-devices --input examples/known-devices-template.csv --output /tmp/proxy-sentinel-known-devices-report.json` | 已通过，示例模板提示需扩展到 30-50 台 |
| 人工样本与身份回放比对 | `go run ./cmd/proxy-sentinel validate known-devices --input examples/known-devices-template.csv --events examples/identity-account-sharing.jsonl --output /tmp/proxy-sentinel-known-devices-compare.json` | 已验证失败路径，不匹配样本返回 comparison failure |
| 复核状态回流 | `POST /labels` -> `GET /ips/{ip}/risk` / `GET /risks` / `GET /overview` | 已通过，已复核 high/confirmed 不再计入 pending reviews |
| 负证据降权 | `go test ./internal/risk` | 已通过，false_positive/benign/needs_more_data 可保留 raw risk 并调整最终等级 |
| 复核证据 ID 校验 | `go test ./internal/controlplane` | 已通过，空 `evidence_ids` 标注返回 400 且不写审计 |
| 翻墙证据模型 | `go test ./internal/evidence ./internal/risk` | 已通过，Suricata alert 生成高置信证据，普通 QUIC 仅生成低置信弱证据 |
| 前端静态类型检查 | `npx tsc --noEmit` | 已通过 |
| 前端生产构建 | `pnpm build` | 已通过 |
| 翻墙聚合接口 | `go test ./internal/store ./internal/controlplane` | 已通过，覆盖账号/终端关联、目的对象、规则命中、持续时间、风险与复核状态回流 |
| 翻墙 MVP 三类回放 | `go test ./internal/replay -run TestProxyMVPReplayFixtures -v` | 已通过，明确规则命中进入 confirmed，视频会议与低置信长连接保持 normal/record |
| 翻墙复核页 UI 审查 | 390x844、1280x800、1440x900 浏览器截图 + DOM 样式探针 | 已通过；无横向溢出，按钮/标签不折行，移动端卡片单列，菜单选中态对比度 6.95:1 |
| 前端静态 UI 规范探针 | `rg 'style=\\{' frontend/src` + 菜单选中态对比度计算 | 已通过 |
| 设备发现正式验收报告 | `validate known-devices --strict` | 已通过单元测试；报告覆盖发现率、误合并、重复创建和基础设施污染，真实结论等待人工真值 |
| 现场 8 天影子运行审计 | `evaluate shadow` 只读分析 192.168.0.30 的 1007 次运行 | 采集通过：41,728,439 条标准事件、0 截断、0 畸形；715 个去重评估样本尚未人工复核 |
| 每日分级抽样与误报汇总 | `evaluate shadow --daily-export-dir ...` | 已通过单元测试并对现场 8 天数据生成 8 份抽样文件；待人工提交 labels 后自动计算确认率、Top 10 误报和调整建议 |
| 设备身份历史回填 | `backfill identity --window 7d` | 已从 7,955 条 DHCP 设备事件物化 82 个 endpoint 候选和 7,775 条 IP/MAC 历史，部署时可重复执行 |

## 本周优先级

| 优先级 | 任务 | 原因 |
| --- | --- | --- |
| P0 | P4 每日人工复核 | 真实流量和 8 天连续运行已满足，当前唯一验收缺口是运营人员提交复核标签 |
| P1 | 30-50 台人工验证集 | 这是设备发现和防共享准确率验收的标准答案 |
| P1 | 代理规则与已知应用负证据维护 | 需要用真实误报样本持续完善白名单、企业 VPN、视频会议和系统服务分类 |
