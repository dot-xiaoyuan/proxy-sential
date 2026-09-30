# Proxy Sentinel 菜单与功能修复验收记录

日期：2026-09-30。执行范围为批准方案的三个阶段，未新增数据库迁移、未连接生产流量、未部署。

## 交付内容

| 阶段 | 结果 | 提交 |
|---|---|---|
| 第一阶段 | 查询与图表跳转、真实规则能力、风险等级、历史样本与标注隔离、响应式修复 | `f46af8a` |
| 第二阶段 | 六类菜单、三个新页面、页面拆分、权限与兼容入口、URL 状态 | `a71ba03` |
| 第三阶段 | 风险工作台、影子评估报告、业务详情与技术展开、验收资料 | 本记录所在提交 |

阶段说明：[第一阶段](phase-1.md)、[第二阶段](phase-2.md)、[第三阶段](phase-3.md)。

最终菜单为运营工作台、风险运营、资产与画像、网络分析、策略与验证、系统管理。新增 `/actions`、`/policies/exceptions`、`/settings/sources`；拆分后复用现有查询、审批、撤销与配置组件。

## 行为和证据验收

- 7 天、30 天事件查询保留 app_protocol、传感器和校区；改变筛选清理分页；详情返回恢复来源条件。
- 图表使用稳定 key，展示名称不作为条件；聚合“其他”不跳转。补充真实点击应用协议图表的回归。
- 旧 ingest、安全例外和动作入口保留查询条件；菜单随详情、刷新、URL 标签页正确展开和选中。外站、非登记返回路径以及 IP 返回环路被拒绝。
- 同次运行两个对象、独立证据、共享证据导致的旧标注歧义、补充稳定 ID 标注、时区写法、证据过期与缺失、读取错误、快照引用不一致及越界目录均有回放测试。
- 稳定标注只影响目标样本；实时列表与离线评估共用 ApplySampleReview。原始歧义标签保留，样本仍未复核，不计入真值。
- 历史证据缺失或读取失败时禁用确认代理、误报、良性；需补数据仍可记录。详情不会回退到当前 IP 证据。
- 稳定样本 ID 前后空白被接口拒绝，回归先复现绕过历史证据校验的问题，再验证修复。
- viewer、reviewer、operator、admin 的用户管理直接访问、校园例外读写、样本标注边界均验证；无 users:manage 时不发用户查询。
- 人为令连接器、用户接口失败后，动作记录与校园例外仍正常加载。
- 影子报告未生成和读取失败分别展示状态或错误，不给出通过结论。

## 验证命令与结果

| 检查 | 结果 |
|---|---|
| `go test ./internal/controlplane ./internal/evaluation ./internal/store` | 通过，新证据回放和接口回归先执行 |
| `go test ./...` | 通过 |
| `pnpm -C frontend test` | 15 个测试文件、36 项测试通过 |
| 前端目录执行 `npx tsc --noEmit` | 通过 |
| `pnpm -C frontend build`，包含 `tsc -b` | 通过 |
| `pnpm -C frontend e2e --workers=3` | 113 项全量回归通过 |
| 最后界面调整后的菜单、详情与工作台回归 | 菜单/工作台 22 项、图表点击 2 项、业务标识和错误保留 1 项、规则导入和布局 2 项通过 |

浏览器回归使用开发 Mock 回放；后端接口测试读取真实临时历史运行文件。未对生产数据库、真实连接器和处罚执行做联调。

## 截图、DOM 与规范对比

验收目录：仓库下 `artifacts/menu-repair-20260930/`。

- `final/menu-repair-all-menu-layout-and-style-probes-{390,1280,1440}-chromium/`：25 个菜单或标签页 × 3 视口，共 75 张页面截图与 DOM JSON。
- `final/menu-repair-sample-and-business-details-{390,1280,1440}-chromium/`：样本证据抽屉、复核弹窗、审计详情、影子详情与采集诊断详情截图。
- `contact-sheet-{390,1280,1440}.png`：工作台、事件、策略、影子、接入与审计对照图。

验证 390×844、1280×800、1440×900 的页面和内部容器溢出；按钮、标签、状态保持 nowrap 和 flex-shrink:0；移动复杂表格使用卡片；固定操作列额外检查按钮是否超出所在单元格。选中态按实际计算样式测量对比度，实测最低 6.95:1，断言 ≥4.5:1；卡片圆角 8px，移动/桌面内边距分别 14px/20px。最后截图检查进一步加宽工作台固定操作列，避免文字被单元格裁切。

## 提交边界与剩余事项

本次开始时，仓库已有较多未提交的设备、4K 和策略重构及未跟踪文件。本次未提交或覆盖这些既有工作。

能安全分离的改动进入三个阶段提交。以下七个重叠文件的本次修改保留在最终工作区，增量保存为 [workspace-overlap.patch](workspace-overlap.patch)：

- `frontend/src/pages/OverviewPage.tsx`
- `frontend/src/pages/PoliciesPage.tsx`
- `frontend/src/pages/ActionsPage.tsx`
- `frontend/src/features/policies/PolicyStrategyEditor.tsx`
- `frontend/tests/e2e/policies.spec.ts`
- `frontend/tests/e2e/overview-workbench.spec.ts`
- `frontend/tests/e2e/product-policy-import.spec.ts`

该零上下文补丁用于审阅，基于任务开始时的文件内容；最终工作区已经包含补丁，不应重复应用。验收和候选构建基于完整工作区，单独检出这三个提交不能重建最终状态。发布源码前仍需把原有工作与上述重叠修改统一归档；本记录不声称获得了干净 Git 提交对应的正式发布版本。

详情只翻译状态或级别字段，业务标识和真实错误保留原文；设备特征库额外完成三个视口的截图和 DOM 检查；加载时显示加载状态，缺失版本、来源和模式不使用硬编码填充。

功能验收无阻断项。风险规则热重载保持 disabled，没有权威规则版本时显示空内容。现有 Ant Design 的 List 等组件仍会输出弃用提示，未影响本次行为和布局验收。

## 候选构建

`artifacts/menu-repair-20260930/menu-repair-20260930-rc1.tar.gz` 保存 Linux/amd64 控制面二进制和生产前端资源；manifest 记录源码摘要和工作区来源，并附 SHA256 校验。它是依赖现有配置和资产的增量候选包，不包含迁移、环境配置或自动部署步骤。
