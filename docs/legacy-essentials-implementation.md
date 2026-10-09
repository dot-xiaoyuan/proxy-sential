# 旧系统精华补齐实现说明

本文记录旧 4K 防代理系统中保留能力的落点和现场上线边界。旧 Redis、厂商 SDK、原始 Zeek/Suricata 字段均停留在适配层，核心仍只处理标准事件、证据、风险和动作协议。

历史记录：下表中的影子评估报告、定时器与分层样本页面已下线，不代表当前功能。

## 检测验收推进表

本轮只完成检测准确性验收。30 保持单机检测，194 只生成流量，真实身份桥和北向处罚不在本轮启用。结果统一写入 `artifacts/detection-acceptance/2026.09.07-detection7/`，现场副本写入 `/opt/proxy-sentinel/data/acceptance/2026.09.07-detection7/`。

| ID | 优先级 | 任务 | 状态 | 负责人 | 结果与验收结论 |
|---|---|---|---|---|---|
| D01 | P0 | 修复影子评估输出目录并恢复定时报告 | 已通过 | Codex | 30 已生成 `shadow/evaluation/latest.json`；systemd 单次任务退出码 0，定时器正常 |
| D02 | P0 | 完善 194 流量生成和 30 侧场景验证器 | 已通过 | Codex | 生成器只报告 `generated`；验证报告包含事件、证据、risk/basis、案件和物化延迟 |
| D03 | P0 | 运行 194 六个直播场景 | 已完成（6/6） | Codex | 普通单终端 normal；双/三终端分别 high/confirmed shared；WireGuard、OpenVPN 均为 high/explicit 且命中高置信规则；纯行为场景无升级；物化延迟 4–7 秒 |
| D04 | P0 | 黄金集边界及规则版本差异验证 | 已通过 | Codex | `golden/`：14/14 事件有效；单 DHCP 与加速器 0 分，IPv6 TTL 为 normal，显式 VPN 为 high/explicit；detection6→7 等级 6/6 一致 |
| D05 | P0 | Ingest 幂等、崩溃、坏行、截断、轮转及存储故障测试 | 已通过 | Codex | `ingest-fault.json`：重启/轮转/截断/坏行/存储不可用/SIGKILL 后恢复，6 个事件、可见重复 0、坏行隔离 1 |
| D06 | P0 | 两倍现场峰值性能与时效测试 | 已通过 | Codex | `performance-60m.json`：持续 3600 秒写入 2,113,200 条，重复 0；可见延迟 P95 2.349 秒、写入 P95 723ms、积压峰值 267,050B、追平 0 秒、批次失败/OOM 0，ready API 95ms |
| D07 | P1 | 离线指纹文件状态与 PostgreSQL 版本台账对齐 | 已通过 | Codex | PostgreSQL 台账激活版本 `offline-2026.09.07-detection7-r2`，状态 ready、规则 9、回填 62 条，与部署文件一致 |
| D08 | P0 | 连续 7 天人工影子复核 | 进行中（观测 5 天，人工 0 天） | 用户复核、Codex 汇总 | 截至 2026-09-08 已生成 5 天分层样本，仍有 12 个日期/风险等级分桶未复核；“影子分层复核”页面完成三视口验收；候选准确率需≥95% |
| D09 | P0 | 汇总检测验收报告 | 待开始 | Codex | 所有 P0 通过后才允许进入身份接入阶段 |
| D10 | P0 | 固化并部署 `2026.09.07-detection7` | 技术部署通过，待最终固化 | Codex | 30 当前 release `2026.09.07-detection7-r2-ui2`；doctor 全绿、6 个核心服务正常、规则 12、登录/API 200、动作 0；全部验收通过后再固化最终包 |

194 上的 `run-194.sh` 只把结果记为 `generated`。流量结束并等待分钟级物化后，在开发机执行：

```bash
scripts/testbed/verify-30.sh \
  --scenario-result artifacts/detection-acceptance/2026.09.07-detection7/<scenario>.json \
  --target root@192.168.0.30 \
  --subject-ip 192.168.0.194
```

验证器只信任 30 上该时间窗内的标准事件、证据、风险和案件数据，并以非零退出码表示场景失败。

## 已实现的代码能力

| 任务 | 实现落点 | 现场启用前检查 |
|---|---|---|
| T01 采集账本 | PostgreSQL `ingest_checkpoints`、`ingest_batches`；原始记录生成稳定事件 ID；ClickHouse 写入前按 `event_id` 收敛 | 执行迁移 014；用实际轮转策略做一次崩溃前后重放 |
| T02 实时采集 | `proxy-sentinel ingest run` 常驻消费 EVE 与 Zeek 日志，完整行批处理、断点续传、轮转/截断恢复、坏行隔离、优雅退出 | 由 systemd 托管；批量、轮询和存储超时按峰值压测结果配置 |
| T03 可观测性 | `/metrics`、空闲心跳、采集 lag、坏行率、ClickHouse 事件写入耗时、通用 webhook 阈值告警 | Prometheus 抓取 `/metrics`；设置告警 webhook 并演练存储故障 |
| T04 旧身份桥 | `legacy-4k-identity-bridge` 全量同步在线表，并以 processing/dead list 可靠消费上下线事件 | Redis 密码和身份接入 token 仅放 `0600` 密钥文件；核对现场 key/list 名称 |
| T05 旧北向桥 | `legacy-northbound-bridge` 校验核心 HMAC，转换动作协议，持久化幂等结果；撤销统一转为 release | 连接器先设 shadow；验证厂商返回字段和超时语义 |
| T06 新旧对账 | `proxy-sentinel evaluate compare --current ... --legacy ...` 输出逐 IP 分歧原因；原影子评估继续负责分层抽样与生产门槛 | 连续运行 7 天并完成单校区灰度、紧急停止和撤销演练 |
| T07/T08 局域网与 TTL | Zeek mDNS/NBNS/LLMNR/TTL 日志适配为 `device` 事件；TTL 归一为初始 TTL/跳数簇，规则最高只到 suspicious | 先确认镜像点和 Zeek 脚本能稳定产出字段；核心不得读取其原始日志 |
| T09 指纹精华 | 游戏加速器规则带来源、许可、版本，进入离线指纹 bundle v3；命中仅作负证据和解释，可随 bundle 回滚 | 只纳入许可清晰且有样本依据的规则；升级前后跑黄金集差异 |
| T10 黄金回放 | `examples/replay/golden-legacy-essentials.jsonl` 覆盖热点、多设备、TTL、VPN、加速器、模拟器、IPv6、基础设施和身份换绑 | 现场 pcap 必须先脱敏并转换为标准事件，不保留旧实现细节断言 |
| T11 OIDC | 可选 OIDC Authorization Code + PKCE，校验 state/nonce；组映射本地角色；IdP 故障时服务仍启动并保留本地管理员入口 | 执行迁移 015；客户端 secret 使用文件；确认回调 URL、组 claim 和停用用户行为 |
| T12 运营输出 | 通用 webhook；`POST /api/v1/exports` 异步生成风险、证据、案件、动作或审计 CSV，支持时间范围、RBAC、审计和下载 | 导出目录仅服务账号可读；按磁盘容量设置外部清理策略 |

## 实时采集示例

```bash
proxy-sentinel ingest run \
  --sensor-id campus-a \
  --eve /var/log/suricata/eve.json \
  --zeek-dhcp /var/log/zeek/current/dhcp.log \
  --zeek-mdns /var/log/zeek/current/mdns.log \
  --zeek-nbns /var/log/zeek/current/nbns.log \
  --zeek-llmnr /var/log/zeek/current/llmnr.log \
  --zeek-ttl /var/log/zeek/current/ttl.log \
  --postgres-dsn "$PROXY_SENTINEL_POSTGRES_DSN" \
  --clickhouse-dsn "$PROXY_SENTINEL_CLICKHOUSE_DSN" \
  --alert-webhook "$PROXY_SENTINEL_INGEST_ALERT_WEBHOOK"
```

`ingest run` 不提供自管的 `start/stop/restart`。生产环境使用 systemd 的 `Restart=on-failure`、`TimeoutStopSec` 和日志策略托管进程。

## OIDC 配置

控制面增加以下参数：`--oidc-issuer`、`--oidc-client-id`、`--oidc-client-secret-file`、`--oidc-redirect-url`、`--oidc-role-mapping` 和 `--oidc-default-role`。角色映射是 JSON，例如：

```json
{"campus-security-reviewers":"reviewer","campus-security-operators":"operator"}
```

未匹配组默认只能得到 `viewer`。OIDC 账号停用后不会因再次登录被自动启用。本地 PostgreSQL 管理员登录始终保留用于 IdP 故障处置。

## 异步导出协议

创建任务：

```http
POST /api/v1/exports
Content-Type: application/json

{"kind":"evidence","from":"2026-09-01T00:00:00Z","to":"2026-09-02T00:00:00Z"}
```

随后查询 `GET /api/v1/exports/{export_id}`；状态为 `completed` 后访问 `GET /api/v1/exports/{export_id}/download`。同一实例最多并行两个导出任务，单任务最多 100000 行，证据导出最多扫描 5000 个风险主体。

## 不能由代码替代的验收门槛

以下事项仍必须在真实校园流量和真实北向沙箱中执行，不能用单元测试宣称完成：连续 7 天影子准确率、基础设施/VPN/教学科研对象零误处置、30 测试机峰值两倍的性能压测、单校区灰度、全局停止和人工撤销演练。在这些门槛通过前，连接器必须保持 shadow，自动处置不得启用。
