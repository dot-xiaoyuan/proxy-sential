# 前端架构设计

## 目标

Proxy Sentinel 前端第一阶段是检测运营台，不是采集调试器或处罚控制台。页面围绕标准事件、证据、风险快照、标注、影子运行和审计展开，不能读取或展示 Suricata 原始专属结构。

技术栈：

- Vite + React + TypeScript。
- Ant Design 作为组件和表单系统。
- TanStack Query 管理服务端状态。
- MSW 提供 mock-first 开发。
- Vitest 与 Playwright 覆盖组件和核心流程。

## 信息架构

- `/overview`：风险等级分布、待复核数量、最近影子运行、Top evidence。
- `/risks`：风险 IP 列表，筛选条件进入 URL query。
- `/ips/:ip`：IP 详情，展示 RiskSnapshot、Evidence、标准事件样本和标注表单。
- `/review`：人工复核队列，面向 reviewer/operator。
- `/shadow-runs`：影子模式运行历史。
- `/settings/rules`：规则 reload 占位，第一阶段只允许影子模式。
- `/audit`：审计日志占位。

## API 契约

`schemas/control-plane-v1.openapi.yaml` 是前后端共同契约源。前端通过 `openapi-typescript` 生成 `frontend/src/shared/api/generated.ts`，页面和 mock 都使用生成类型。

第一阶段真实接口由 `proxy-sentinel control-plane serve` 提供。控制面通过
`internal/store` 读取数据；30 机器过渡期使用 `dual` 模式兼容文件产物，生产目标
是 PostgreSQL + ClickHouse，不再依赖 `data/shadow/runs/*` 作为主存储。

接口：

- `GET /api/v1/session`
- `GET /api/v1/overview`
- `GET /api/v1/risks`
- `GET /api/v1/ips/{ip}/risk`
- `GET /api/v1/ips/{ip}/evidence`
- `GET /api/v1/ips/{ip}/events`
- `GET /api/v1/ingest/status`
- `GET /api/v1/ingest/diagnostics`
- `GET /api/v1/ingest/event-types`
- `GET /api/v1/ingest/errors`
- `GET /api/v1/events`
- `POST /api/v1/labels`
- `GET /api/v1/shadow/runs`
- `GET /api/v1/audit-logs`
- `POST /api/v1/rules/reload`

默认启动命令：

```bash
proxy-sentinel control-plane serve \
  --addr :8080 \
  --shadow-dir /opt/proxy-sentinel/data/shadow \
  --sensor-id office-30 \
  --frontend-dir /opt/proxy-sentinel/frontend/dist \
  --storage-mode dual \
  --read-only
```

第一版 `POST /api/v1/labels` 返回 403，`POST /api/v1/rules/reload` 返回
`disabled/shadow`，用于保证控制台只做真实数据只读呈现。

## 权限

第一阶段使用固定 session，不实现真实登录。权限点包括：

- `risks:read`
- `evidence:read`
- `events:read`
- `labels:create`
- `shadow:read`
- `audit:read`
- `rules:reload`

真实 read-only 控制面不会下发 `labels:create` 和 `rules:reload`。缺少权限时，
页面仍可展示上下文，但相关按钮必须禁用并给出明确原因。

## 设计约束

- 风险分必须始终和证据 ID、解释文本一起展示。
- `domain_diversity`、`port_distribution` 这类弱证据不能在 UI 上被包装成确认代理。
- 表格、详情、复核表单要优先支持中文运营人员扫描。
- IPv6、长 User-Agent、长 evidence reason 必须换行，不能撑破布局。
- 空态、错误态、加载态和 mock 标记必须完整。

## 验收

- `pnpm generate:api`
- `pnpm typecheck`
- `pnpm lint`
- `pnpm test`
- `pnpm e2e`
- 桌面 1440px、笔记本 1280px、移动 390px 无重叠。
