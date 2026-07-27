# 前端任务拆分

## 交付规则

每个 Antigravity 任务必须包含：

- 变更摘要。
- 页面截图或 Playwright 结果。
- 已知限制。
- 是否仍在使用 mock API。
- 影响的接口、路由和权限点。

## Task 0：工程骨架

目标：完成 `frontend/` Vite React 工程、Ant Design 主题、路由、QueryClient、MSW 和基础布局。

验收：

- `pnpm dev` 可启动。
- 左侧导航能进入全部第一阶段路由。
- mock API 默认启用，页面有 mock 标记。

## Task 1：API 契约

目标：维护 `schemas/control-plane-v1.openapi.yaml` 并生成 TypeScript 类型。

验收：

- `pnpm generate:api` 可重复执行。
- 页面和 mock handlers 不手写重复 DTO。
- 禁止新增 Suricata 原始字段依赖。

## Task 2：风险列表

目标：实现 `/risks`，支持等级、sensor、关键词筛选和分页占位。

验收：

- 筛选条件进入 URL query。
- normal/suspicious/high/confirmed 四级样本可展示。
- 空态、错误态、加载态完整。

## Task 3：IP 详情

目标：实现 `/ips/:ip`，展示风险摘要、证据解释、标准事件样本和标注表单。

验收：

- 每个风险判断都能追溯 evidence IDs。
- 标注必须填写原因。
- 长样本文本不撑破布局。

## Task 4：复核与影子运行

目标：实现 `/review` 和 `/shadow-runs`。

验收：

- 复核队列可提交确认代理、误报、良性、需要更多数据。
- 影子运行可展示 offset、truncated、normalized/evidence/risk 数量。

## Task 5：权限、审计、规则占位

目标：补齐 `/audit` 与 `/settings/rules`。

验收：

- 缺少权限时按钮禁用。
- rule reload 第一阶段只显示影子模式。
- 审计日志能记录 mock 标注行为。

## Task 6：测试

目标：补齐 Vitest 和 Playwright。

验收：

- 风险等级、Evidence 渲染、权限禁用、标注校验有单测。
- 风险筛选、IP 详情标注、shadow run 浏览有端到端测试。
