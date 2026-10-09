# 验收关口推进 Runbook

本 Runbook 把 `docs/shared-access/alignment-ledger-20260918.md` 的"下一个关口"落成可执行的命令与判定标准。目标不是新增功能，而是让"能不能开人工处置"变成可复现的结论。自动灰度保持关闭。

关口顺序：**身份权威清单 → 检测准确率 → 人工下线闭环 → 原生能力矩阵**。任一关口的 blocker 未清空，不得进入下一关口的真实处置。

## 零、前提

- 30 已部署当前版本，PostgreSQL / ClickHouse 与常驻服务正常（`/readyz` 全 ready）。
- 190 管理 API 地址、Pinned 证书（PEM）已核实；4K 数据库授权已在管理端保存。
- 私密探针配置为 `0600` 普通文件、不超过 64 KiB，字段固定为：

```json
{
  "endpoint": "https://<management-host>:8001",
  "app_id": "<app-id>",
  "app_secret": "<app-secret>",
  "certificate_file": "/path/to/management.pem"
}
```

管理凭据与密码不写入代码、文档示例或日志。

## 一、关口 1：身份权威清单契约

### 1.1 运行契约探针（只读）

```bash
proxy-sentinel-probe() {
  go run ./cmd/srun-api-probe --config "$PROBE_CONFIG" "$@"
}

# 连通性基线
proxy-sentinel-probe --mode total

# 权威清单契约判定（逐端点 shape/fields/complete/blocker + 总判定）
mkdir -p artifacts/identity-contract-$(date +%Y%m%d)
proxy-sentinel-probe --mode capability \
  | tee artifacts/identity-contract-$(date +%Y%m%d)/capability.json

# 指定账号只读观测（只输出字段名与行数，不回显任何值）
proxy-sentinel-probe --mode account --account yuantong \
  | tee artifacts/identity-contract-$(date +%Y%m%d)/account.json
```

判定（`--mode capability` 输出的 `verdict`）：

- `completeness = proven`：至少一个端点声明 `complete=true`，且必需字段齐全 → 可配置 `complete_inventory` 身份源。
- `completeness = unproven`：进入 1.2。**这是 190 原生端点的预期结果**，`online-equipment` / `online-data` 没有原子快照与缺席契约。
- 加 `--strict` 时非 proven 退出码为 1，可直接用于 CI/巡检。

必需字段（与 `internal/srunapi/inventory_http.go` 和 `internal/legacy4k/snapshot.go` 一致）：

`rad_online_id`、`session_id`、`user_name`、`add_time`（登录代次），地址字段 `ip|ipv6|ip6` 至少一个。

**禁止**：把 `online-equipment` 返回的空数组判定为"用户离线"；`account.json` 的 `absence_verified=false` 就是明确结论。

### 1.2 分支：提供 `online-inventory/v1` 生产者

当 verdict 为 `unproven` 时，需要一个能证明完整的清单源。契约由 `internal/srunapi/inventory_http.go:50-97` 固定，生产方必须满足：

- `HTTPS GET`，`Authorization: Bearer <token>`，禁止重定向，响应 ≤16 MiB，未知字段拒绝（`DisallowUnknownFields`）。
- 顶层字段：`schema_version="online-inventory/v1"`、`instance_id`、`observed_at`、`campus_id`、`access_domain`、`complete=true`、`expected_count`、`rows`。
- `expected_count == len(rows)`；`observed_at` 为 UTC、不晚于当前时间、**不超过 5 秒**、微秒对齐（`Nanosecond()%1000 == 0`）。
- 每行必需：`rad_online_id`（唯一、无首尾空白）、`session_id`、`user_name`、`add_time`（unix 秒字符串、正值、非未来、规范整数）、`ip|ipv6|ip6` 至少一个且非组播。
- 建议保留：`user_mac`、`nas_ip`、`group_id`、`products_id`、`device_id`。

数据源与部署位置（认证 MySQL `rad_online` 表，或认证 Redis `hash:rad_online:*`；部署在 190 或独立主机）需要与厂商确认。**不要把 Redis 直连暴露给 Sentinel**：非回环 Redis 回放被明确拒绝，桥接必须以 HTTPS 契约对外。

### 1.3 配置身份源并只读确认

管理端「处置网关 → 连接器 → 身份来源与范围」：

1. 选择来源类型：原生 `online_equipment` 或 `complete_inventory`（后者填 `inventory_url` + token）。
2. 填写用户网段、校区、接入域；保存后观察状态变为 ready，最近观测时间在 5 秒内。
3. 只读确认指定账号 `yuantong / 192.168.0.93`；重新认证后确认关联，不把"接口空数组"当离线。
4. 记录：来源状态、观测时间、阻塞原因、确认时间，归档到 `artifacts/identity-contract-<date>/`。

**通过标准**：身份源 ready，最近观测 ≤5 秒，指定账号只读关联可复现；失败时系统按既有设计停止身份准入。

## 二、关口 2：检测结果人工核对

在「风险案件」和「账号复核」中查看标准事件、证据、评分与解释，针对真实业务样本记录人工结论和证据 ID。准确率与误报情况由验收人员依据这些记录统计，并在现场验收材料中说明样本范围、统计方法和结论。

### 2.1 设备发现人工标准答案（并行）

```bash
go run ./cmd/proxy-sentinel validate known-devices \
  --input examples/known-devices-template.csv \
  --events <DHCP 标准事件回填文件> \
  --output artifacts/known-devices-<date>.json
```

需要人工填写 30–50 台真实设备的标准答案；无代码改动。

## 三、关口 3：人工下线闭环现场验收

只对指定测试账号执行，全程保留影子准入、审计、冷却、发送前撤销与紧急停止。

1. 产生/定位一条共享复核（`/shared-access/reviews`）。
2. 写入人工结论：`POST /api/v1/shared-access/reviews/{id}/conclusion`。
3. 预览：`POST /api/v1/shared-access/reviews/{id}/disconnect-preview`。
4. 提交：`POST /api/v1/shared-access/reviews/{id}/disconnect`。
5. 覆盖边界并记录实际行为：重复确认、身份/会话变化、多会话、部分失败、证据过期、证据不足——预期为 blocked 或要求重新复核。
6. 恢复验证：重新认证而不是"注销"。不得把管理员下线当成用户注销。

**通过标准**：指定账号完整链路记录（页面或 API）+ 审计条目；未验证项明确列出。合成流量结果不代表真实校园网准确率。

## 四、关口 4：原生能力矩阵

用 1.1 的探针记录已确认能力，逐项补齐"已确认 / 未确认 / 不存在"：

| 能力 | 现状 |
|---|---|
| 管理鉴权（令牌申请） | 已确认 |
| 在线总数 | 已确认（仅连通性探针） |
| 账号级只读查询 | 已确认，但无完整/缺席契约 |
| 管理员下线 `online-drop` | 已确认，仅 `drop_type=radius` 受理；必须独立核验会话消失 |
| 限速 / 停用 / 恢复 | 未确认 |
| 用户注销 | 未确认（不映射为停用/删除） |
| 期限处罚 / 名单 | 未确认 |

**通过标准**：能力矩阵归档到 `docs/`，每项标注证据与阻塞原因；据此决定是否立项"通知原生送达"与"期限处罚"。不存在原生接口的能力不实现。

## 五、失败模式与禁止事项

- 探针：非 HTTPS、证书不匹配、鉴权失败、超时、重定向、超限、缺字段、`complete=false`、`expected_count` 与行数不符、`observed_at` 超 5 秒、`rad_online_id` 重复、`add_time` 非规范整数——全部明确失败，**不产生空清单**。
- 账号查询返回空：只报 `absence_verified=false`，不得输出"离线"。
- 身份源失败：沿用"失败即停止身份准入"，不因探针/桥接故障放宽处置。
- 准确率：零值门槛不启用（保持既有部署行为）；只有正常标签不满足候选门槛。
- 禁止事项：不 SSH 190 修改认证系统；不发送真实下线以外的控制请求；不用 Redis 回退补齐缺失契约；不把代码改动或隔离测试冒充现场验收。
- 不清理现场业务数据，不做全量备份以外的破坏性操作。

## 六、记录归档

每轮在 `artifacts/` 下建立日期目录，至少包含：

- `capability.json` / `account.json`：契约探针原始输出。
- 身份源状态与指定账号只读确认记录。
- `shadow-eval-<date>.json`：准确率门槛报告。
- 人工下线闭环记录与审计条目。
- 前端若改动：三视口截图、DOM 探针与规范比对。

报告只写实测结果，不把"代码完成"当作"验收通过"。
