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

## Task 7：事件检索页

目标：实现 `/events`，面向标准事件检索和详情查看。

验收：

- 支持时间范围、sensor、源 IP、目的 IP、域名、User-Agent、端口、协议和事件类型筛选。
- 支持分页和事件详情抽屉。
- 事件详情只展示 NormalizedEvent 字段，不展示 Suricata 原始 EVE。
- 390px 移动端下复杂表格卡片化或横向安全滚动，不出现按钮竖排和内容遮挡。

## Task 8：访问对象详情页

目标：实现 domain、dst IP、User-Agent、JA3/JA4 的访问对象钻取。

验收：

- `/activity` Top domains、HTTP Host、TLS SNI、目的 IP、User-Agent、JA3/JA4 可跳转。
- 详情页展示关联 IP、风险等级分布、事件趋势和标准事件样本。
- 长域名、IPv6、长 UA、长 JA3/JA4 不撑破布局。

## Task 9：运营体验补强

目标：让控制面从“能看”提升到“可运营”。

验收：

- 访问态势、采集诊断、风险列表支持自动刷新和数据更新时间提示。
- 空态、错误态、加载态文案清晰，明确当前是否 Mock API。
- 所有按钮、标签、状态 Badge 和操作项文本不折行成竖排。
- 前端改动必须通过截图捕获、DOM 样式探针和设计规范对比。
- 390x844、1280x800、1440x900 三视口均通过 Playwright UI audit。

## Task 10：复核闭环 UI

目标：配合 labels 落库，完成真实人工复核工作流。

验收：

- `/review` 显示复核队列、复核状态、历史标注和审计结果。
- IP 详情页可提交确认代理、误报、良性、需要更多数据。
- read-only 模式按钮禁用并解释原因；可写模式提交成功后刷新风险和审计。
- 标注原因必填，提交结果可追溯。
