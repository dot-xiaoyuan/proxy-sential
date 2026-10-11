# 全页面测试报告（2026-10-11）

## 1. 测试范围与环境

| 项目 | 内容 |
|------|------|
| 工作区 | `/Users/yuantong/Developer/Projects/golang/proxy-sentinel`（主工作区） |
| 分支 / 提交 | `codex/menu-function-repair-20260930` @ `2493abb` |
| 工作区状态 | 23 项未提交改动（含本次新增的测试规格），未做任何清理或提交 |
| 测试时间 | 2026-10-11 18:49–19:00 |
| 数据来源 | MSW mock 模式（`VITE_ENABLE_MOCKS=true`），Playwright `webServer` 拉起 `pnpm dev`，`127.0.0.1:5175` |
| 视口 | 390×844（移动）、1280×800（笔记本）、1440×900（桌面） |
| 覆盖清单 | `frontend/src/app/router.tsx` 全部 **35 条路由**（21 静态页面 + 11 动态详情 + 3 遗留重定向）+ 12 条 tab/section 变体 = **47 个 URL** |
| 执行方式 | `pnpm exec playwright test tests/e2e/all-pages-audit.spec.ts --workers=1` |
| 新增规格 | `frontend/tests/e2e/all-pages-audit.spec.ts` |
| 证据产物 | `frontend/test-results/all-pages-audit-全页面遍历-<视口>-chromium/all-pages.json` + `shots/*.png`（共 141 张全页截图，目录已被 `.gitignore` 忽略） |

测试目标是**同一个页面在不同视口下的完整一遍遍历**，逐页采集：渲染成功性、页面标题、JS 运行时错误、控制台错误、HTTP ≥400 与未 mock 接口、导航取消请求、文档横向溢出、容器内部溢出、按钮/标签 nowrap 与 `flex-shrink`、操作按钮越界、固定列裁切、禁用缺省文案、横杠占位、长标识符换行策略、选中菜单对比度、宽表格滚动行为。

**路由清单完整性由测试自身保证**：`路由清单与 router.tsx 完全对齐` 用正则读取 `router.tsx` 并断言 35 条路由与 47 条清单互相无遗漏、无多余，后续新增页面会立刻让该用例变红。

## 2. 结果总览

**141 次页面加载（47 × 3），140 次通过，1 项问题。**

| 视口 | 通过 | 问题 |
|------|------|------|
| 390×844 | 47 / 47 | 0 |
| 1280×800 | 46 / 47 | 1 |
| 1440×900 | 47 / 47 | 0 |

各类检查项的全局统计：

| 检查项 | 结果 |
|--------|------|
| 页面渲染（有内容 + 有可见标题） | 141 / 141 成功 |
| `pageerror`（JS 运行时异常） | 0 |
| 禁用缺省文案（未识别/未获取/未关联/未观测/未知/待关联） | 0 |
| 横杠占位（`—`/`–`） | 0 |
| 文档横向溢出 | 0 |
| 容器内部溢出（不可滚动） | 0 |
| 按钮/标签 nowrap + `flex-shrink: 0` 违规 | 0 |
| 固定列按钮被裁 | 0 |
| 选中菜单对比度 < 4.5:1 | 0 |
| 长标识符缺少换行/截断策略 | 0 |
| 接口返回 ≥400 | 0 |
| 未 mock 走到真实网络的接口 | 0 |
| “没有访问权限”误拦 | 0 |
| 控制台 `error` 级输出 | 27 次页面访问（均为 antd 6 弃用告警，见 P2-01） |
| 导航取消请求（`ERR_ABORTED`） | 3 次（见 P3-02） |

**稳定性**：连续两次完整运行，问题集合完全一致（均为下方 P1-01 一项），无抖动。

首屏内容耗时最高的页面为 `/overview`（约 830–840ms，仍在既有 `ui-audit` 的 1.5s 冷启动预算内）与 `/activity`（约 826ms）。

## 3. 问题清单

### P1-01 `/policies/destination-targets` 在 1280×800 下操作列溢出视口

- **现象**：`内网目标访问检测 → 检测规则` 表格的「操作」列未被固定，末列按钮被推出视口右边界。实测「删除」按钮 `right = 1328px`，视口宽度 `1280px`，超出 48px；首屏只能看到被右边界切掉一半的「试算」按钮，编辑/删除必须横向滚动表格才能触达（macOS 下滚动条默认隐藏，用户难以察觉）。
- **证据**：
  - 探针记录：`frontend/test-results/all-pages-audit-全页面遍历-1280x800-chromium/all-pages.json` → `records[url="/policies/destination-targets"].findings[0].detail`
  - 截图：`frontend/test-results/all-pages-audit-全页面遍历-1280x800-chromium/shots/policies-destination-targets-1280.png`
- **对照**：同一问题本可避免——`/discovery` 的宽表格（内容 1605px > 容器 978px）把「操作」列以 `position: sticky; right: 0`（antd 6 的 `ant-table-cell-fix-end`）钉在容器右边缘，实测位于 1155–1245px，`查看详情` 链接在 1169–1225px，首屏完全可见；`/settings/behavior-reports` 的 `测试/试算/编辑/删除` 也全部在视口内。**只有 `/policies/destination-targets` 缺少该处理**，属该页面的独立缺陷。
- **影响范围**：仅 1280×800；390×844 与 1440×900 下按钮均在视口内（390 下表格已卡片化）。
- **根因**：该表格设置了横向滚动但没有给操作列 `fixed: 'right'`，也没有压缩列宽；其余同类表格要么固定了操作列，要么总宽未超出容器。
- **修复建议**：给该表格操作列加 `fixed: 'right'`（与 `/discovery` 一致），或减少列宽/`scroll={{ x }}` 取值使其在 1280 内不溢出。改动位置在 `frontend/src/pages` 下目标地址策略页的表格列定义（`destination-targets` 相关列配置）。工作量：约 0.5 小时，需回归 390/1280/1440 三视口。

### P2-01 antd 6 弃用告警（工程债，非页面缺陷）

27 次页面访问在控制台输出 `error` 级告警，共 3 类：

| 告警 | 次数 | 涉及页面 |
|------|------|----------|
| `[antd: List]` List 组件已弃用，下一大版本将移除 | 18 | `/cases`、`/settings/actions`、`/settings/organization`、`/actions?tab=actions`、`/risks`、`/review` |
| `[antd: Drawer]` `width` 已弃用，应改用 `size` | 9 | `/settings/sources`、`/settings/sources?tab=diagnostics`、`/ingest` |
| `[antd: Descriptions]` 一行内 `span` 之和与 `column` 不匹配 | 3 | `/settings/sources`、`/settings/sources?tab=diagnostics`、`/ingest` |

前两类是升级遗留的 API 弃用，不影响当前呈现；第三类 `Descriptions` 的 `span` 不匹配是真实的列布局配置问题，可能导致描述项跨列错位，建议随 `List`/`Drawer` 一并整改。工作量：约 2 小时。

### P2-02 宽表格需横向滚动（观察项，非缺陷）

4 处容器内容宽于容器且依赖横向滚动，均提供了 `overflow-x: auto`，属既有允许模式：

| 页面 | 视口 | 容器宽 | 内容宽 | 固定列数 | 首屏核对 |
|------|------|--------|--------|----------|----------|
| `/discovery` | 1280×800 | 978 | 1605 | 3 | 操作列 sticky，内容完整可见 |
| `/discovery` | 1440×900 | 1138 | 1605 | 3 | 同上 |
| `/policies/destination-targets` | 1280×800 | 962 | 1100 | 0 | 操作列未固定，见 P1-01 |
| `/settings/behavior-reports` | 1280×800 | 962 | 1000 | 0 | 操作按钮全部在视口内 |

`/discovery` 在 1440×900 下仍需横向滚动，是清单里唯一在桌面级视口下要求滚动的宽表格；如需彻底免滚动，可考虑隐藏低优先级列或列宽自适应，但当前不构成规范违规。`/policies/destination-targets` 的固定列数为 0，与 P1-01 是同一根因。

### P3-01 `screenshots.spec.ts` 使用硬编码绝对路径（工程问题）

`frontend/tests/e2e/screenshots.spec.ts` 把截图写入 `/Users/yuantong/.gemini/antigravity-ide/brain/e6a8c8d0-1e8f-4b59-996f-0c4e9e39d20a`，换机器或换用户即失效。建议改为 `testInfo.outputPath()`（本次新增规格即按此实现）。工作量：约 15 分钟。

### P3-02 `/devices` 导航取消请求（信息，非缺陷）

3 个视口各记录到 1 次 `GET /api/v1/device-inventory?... net::ERR_ABORTED`，由离开 `/devices` 时 React Query 取消在途请求产生，属正常 SPA 行为，已在规格中归类为信息项而非缺陷。

## 4. 逐页结果矩阵

标记：✅ 通过（该视口下无任何探针发现）；❌ 带有发现项（括号内为类型）。

| # | 路由 | 类型 | 页面标题（首屏） | 390×844 | 1280×800 | 1440×900 |
|---|------|------|------------------|---------|----------|----------|
| 1 | `/overview` | 页面 | 高校网络风险运营工作台 | ✅ | ✅ | ✅ |
| 2 | `/shared-access` | 页面 | 共享发现 | ✅ | ✅ | ✅ |
| 3 | `/cases` | 页面 | 风险案件 | ✅ | ✅ | ✅ |
| 4 | `/actions` | 页面 | 处置记录 | ✅ | ✅ | ✅ |
| 5 | `/devices` | 页面 | 终端画像 | ✅ | ✅ | ✅ |
| 6 | `/discovery` | 页面 | 网络设备发现 | ✅ | ✅ | ✅ |
| 7 | `/activity` | 页面 | 应用访问 | ✅ | ✅ | ✅ |
| 8 | `/events` | 页面 | DPI 标准事件检索 | ✅ | ✅ | ✅ |
| 9 | `/policies` | 页面 | 防代理策略 | ✅ | ✅ | ✅ |
| 10 | `/policies/whitelist` | 页面 | 白名单 | ✅ | ✅ | ✅ |
| 11 | `/policies/blacklist` | 页面 | 黑名单 | ✅ | ✅ | ✅ |
| 12 | `/policies/destination-targets` | 页面 | 内网目标访问检测 | ✅ | ❌ layout-actions | ✅ |
| 13 | `/policies/exceptions` | 页面 | 校园例外 | ✅ | ✅ | ✅ |
| 14 | `/settings/rules` | 页面 | 规则与特征库 | ✅ | ✅ | ✅ |
| 15 | `/settings/sources` | 页面 | 采集诊断与节点性能 | ✅ | ✅ | ✅ |
| 16 | `/settings/actions` | 页面 | 认证与处置接入 | ✅ | ✅ | ✅ |
| 17 | `/settings/organization` | 页面 | 校区与网络区域 | ✅ | ✅ | ✅ |
| 18 | `/settings/security` | 页面 | 用户权限 | ✅ | ✅ | ✅ |
| 19 | `/settings/notifications` | 页面 | 通知模板与通道 | ✅ | ✅ | ✅ |
| 20 | `/settings/behavior-reports` | 页面 | 网络安全行为上报 | ✅ | ✅ | ✅ |
| 21 | `/audit` | 页面 | 系统操作与策略审计日志 | ✅ | ✅ | ✅ |
| 22 | `/shared-access?tab=devices` | 页面 | 共享发现 | ✅ | ✅ | ✅ |
| 23 | `/shared-access?tab=observations` | 页面 | 共享发现 | ✅ | ✅ | ✅ |
| 24 | `/shared-access?tab=reviews` | 页面 | 账号复核 | ✅ | ✅ | ✅ |
| 25 | `/activity?section=applications` | 页面 | 应用访问 | ✅ | ✅ | ✅ |
| 26 | `/activity?section=access` | 页面 | 访问分析 | ✅ | ✅ | ✅ |
| 27 | `/activity?section=technical` | 页面 | 技术指纹 | ✅ | ✅ | ✅ |
| 28 | `/actions?tab=executions` | 页面 | 处置记录 | ✅ | ✅ | ✅ |
| 29 | `/actions?tab=actions` | 页面 | 处置记录 | ✅ | ✅ | ✅ |
| 30 | `/settings/sources?tab=sources` | 页面 | 发现采集配置 | ✅ | ✅ | ✅ |
| 31 | `/settings/sources?tab=scan` | 页面 | 发现采集配置 | ✅ | ✅ | ✅ |
| 32 | `/settings/sources?tab=tasks` | 页面 | 发现采集配置 | ✅ | ✅ | ✅ |
| 33 | `/settings/sources?tab=diagnostics` | 页面 | 采集诊断与节点性能 | ✅ | ✅ | ✅ |
| 34 | `/discovery/routers/router-huawei-ar-001` | 页面 | Huawei · AR6140 · 路由器 | ✅ | ✅ | ✅ |
| 35 | `/devices/endpoint-mi14-ops` | 页面 | 10.255.0.59 | ✅ | ✅ | ✅ |
| 36 | `/events/event-tls-59-b` | 页面 | 事件详情 | ✅ | ✅ | ✅ |
| 37 | `/ingest/diagnostics/diag-20260724-131645` | 页面 | 采集诊断详情 | ✅ | ✅ | ✅ |
| 38 | `/ips/10.255.0.59` | 页面 | 10.255.0.59 | ✅ | ✅ | ✅ |
| 39 | `/review/proxy-review-openvpn` | 页面 | 复核详情 | ✅ | ✅ | ✅ |
| 40 | `/cases/proxy-review-openvpn` | 页面 | 案件 proxy-review-openvpn | ✅ | ✅ | ✅ |
| 41 | `/audit/audit-001` | 页面 | 审计详情 | ✅ | ✅ | ✅ |
| 42 | `/shared-access/observations/shared-behavior-test` | 页面 | 共享网关识别记录：172.21.20.171 | ✅ | ✅ | ✅ |
| 43 | `/shared-access/reviews/review-office-test` | 页面 | 共享复核：yuantong | ✅ | ✅ | ✅ |
| 44 | `/settings/sources/diagnostics/diag-20260724-131645` | 页面 | 采集诊断详情 | ✅ | ✅ | ✅ |
| 45 | `/ingest` | 重定向 | 采集诊断与节点性能 | ✅ | ✅ | ✅ |
| 46 | `/risks` | 重定向 | 风险案件 | ✅ | ✅ | ✅ |
| 47 | `/review` | 重定向 | 风险案件 | ✅ | ✅ | ✅ |

三条遗留重定向均正确落到目标页并保持选中菜单：`/ingest → /settings/sources?tab=diagnostics`、`/risks → /cases`、`/review → /cases`。

## 5. 与既有测试套件的关系

本次**未改动任何产品代码**，只新增一个遍历规格，因此既有套件全部保持绿色：

| 套件 | 结果 |
|------|------|
| `tests/e2e/menu-repair.spec.ts` | 16 / 16 通过（390/1280/1440 全菜单布局探针、角色边界、遗留链接、业务详情下钻） |
| `tests/e2e/ui-audit.spec.ts` | 6 / 6 通过（24 路由 × 4 视口防溢出、内联样式纯净度、冷启动 1.5s、固定表头） |
| `pnpm test`（Vitest） | 25 个文件 / 86 个用例全部通过 |
| `pnpm typecheck` | 通过（含 `check-api-contract.mjs`：API 契约与前端生成类型一致） |
| `pnpm build` | 通过 |

覆盖增量：既有两个套件覆盖了 21 个静态页面与 12 个 tab 变体，但**没有覆盖任何动态详情页**。本次补齐了 11 个动态详情路由（`/discovery/routers/:assessmentId`、`/devices/:endpointId`、`/events/:eventId`、`/ingest/diagnostics/:diagnosticId`、`/ips/:ip`、`/review/:caseId`、`/cases/:caseId`、`/audit/:auditId`、`/shared-access/observations/:observationId`、`/shared-access/reviews/:id`、`/settings/sources/diagnostics/:diagnosticId`）以及 3 条遗留重定向，并把三视口探针合并为一处可复跑的证据源。

复用而非重复：探针逻辑沿用 `menu-repair.spec.ts` 的禁用文案正则与选中菜单对比度算法、`ui-audit.spec.ts` 的溢出判定，未另造一套判定标准。

## 6. 未覆盖与无法判定的部分

- **真实后端行为不在本次结论内**：本轮以 MSW mock 为唯一数据源，用于判定"页面自身缺陷"。后端接口的真实延迟、分页边界、权限矩阵与错误码呈现需另跑一轮（本地 `18080` 上的进程属另一个工作区的旧构建，不能作为本次被测代码的后端）。
- **角色权限矩阵**：本次以 mock 默认会话（operator，含全部 `*:read` 权限）逐页验证渲染，141 次访问均未出现"没有访问权限"。viewer/reviewer/admin 的角色边界由 `menu-repair.spec.ts` 单独覆盖。
- **交互与写入路径**：仅验证首屏渲染与静态布局，未点击提交、审批、导出等写操作。
- **`screenshots.spec.ts` 未执行**（其输出路径为硬编码的机器专属目录，见 P3-01），故本报告未包含该套件的截图产线结果。
- **743×774 视口**未纳入本次清单（`ui-audit.spec.ts` 已覆盖该视口的防溢出检查）。

## 7. 建议修复清单

| 优先级 | 项目 | 位置 | 预计工作量 |
|--------|------|------|-----------|
| P1 | 固定或收窄目标地址策略表格的操作列，使按钮在 1280×800 内可见 | 目标地址策略页表格列定义 | 0.5 小时 |
| P2 | 处理 antd 6 弃用：`List` → 替代组件、`Drawer` 的 `width` → `size` | 涉及 `/cases`、`/actions`、`/settings/actions`、`/settings/organization` 等页 | 1.5 小时 |
| P2 | 修正 `Descriptions` 的 `span` 与 `column` 不匹配 | 采集诊断与节点性能页 | 0.5 小时 |
| P3 | `screenshots.spec.ts` 改用 `testInfo.outputPath()` | `frontend/tests/e2e/screenshots.spec.ts` | 15 分钟 |
| P3 | 评估 `/discovery` 在 1440×900 下仍横向滚动的取舍（隐藏低优先级列 / 列宽自适应） | 网络设备发现页 | 1 小时 |

本轮第一版只做测试与报告，**未修改任何产品代码**；下列修复已于同日经确认后实施（见第 8 节）。

## 8. 修复结果（2026-10-11 同日追加）

### 8.1 已修复

| 编号 | 修复内容 | 改动位置 |
|------|----------|----------|
| P1-01 | 目标地址策略表格操作列加 `fixed: 'right'`，与 `/discovery` 的既有做法一致；「试算/编辑/删除」在 1280×800 首屏完整可见 | `frontend/src/pages/DestinationTargetsPage.tsx` |
| P2-01a | 新建项目自有列表组件 `StackList` / `StackListItem` / `StackListItemMeta` / `StackListActions`，替换 antd 6 已弃用的 `List`（4 个文件、5 处用法）；`index.css` 中 `.ant-list-*` 样式同步收敛为 `.ps-list-*` | `frontend/src/shared/ui/StackList.tsx`（新增）、`frontend/src/shared/ui/index.ts`、`CasesPage.tsx`、`ActionHistory.tsx`、`ActionsPage.tsx`、`OrganizationPage.tsx`、`frontend/src/index.css` |
| P2-01b | `Drawer` 的 `width={640}` 改为 `size={640}`（`AppShell` 早已使用新 API） | `frontend/src/pages/IngestPage.tsx` |
| P2-02 | 去掉「采集说明」的固定 `span={3}`：该值在 xs(1 列)/sm(2 列) 下必然越界触发告警，antd 会自动把不完整行的末项补满，桌面端视觉不变 | `frontend/src/pages/IngestPage.tsx` |
| P3-01 | 截图改用 `testInfo.outputPath()`，去掉机器专属的硬编码绝对路径 | `frontend/tests/e2e/screenshots.spec.ts` |

**修复期间自查发现并纠正的两个问题**（均由三视口截图/DOM 探针发现，未流入最终结果）：

1. `StackList` 空态分支最初丢掉了 `className`，导致 `/actions?tab=actions` 的 `mobile-only` 空态在桌面端可见。已让空态容器同样承接 `className`。
2. 新增的 `.ps-list { display: flex }` 与既有 `.mobile-only { display: none }` 特异性相同且位置更靠后，覆盖了可见性约束，使移动端列表在桌面端露出（antd 原样式用 `:where()` 包裹，特异性为 0，这正是原实现正常的原因）。已改为 `:where(.ps-list)` 保持 0 特异性。
   同时给遍历规格新增 `viewport-visibility` 检查：>560px 不得出现 `.mobile-only`、≤560px 不得出现 `.desktop-only`，防止同类问题再次静默回归。

### 8.2 修复后复测结果

| 项目 | 结果 |
|------|------|
| 全页面遍历 | **141 / 141 通过，问题 0 项**（390×844、1280×800、1440×900 均 47/47） |
| 控制台 `error` 输出 | **0**（antd `List` / `Drawer` / `Descriptions` 三类弃用告警全部消除） |
| `menu-repair.spec.ts` | 16 / 16 通过 |
| `ui-audit.spec.ts` | 6 / 6 通过 |
| `screenshots.spec.ts` | 4 / 4 通过（改用 `outputPath` 后仍正常产出） |
| Vitest | 25 个文件 / 86 个用例通过 |
| `pnpm typecheck` + API 契约 | 通过 |
| `pnpm build` | 通过 |

三视口定点截图复核（`/cases` 移动端案件卡、`/actions?tab=actions` 空态、`/settings/actions` 连接器列表、`/settings/organization` 校区/区域列表）：结构与改造前一致，`/settings/actions` 连接器列表的「标题 + 描述 + 操作行独占一行」布局保持正确，按钮未变形、未横向溢出。

### 8.3 未做修改的评估项

**P3-02 `/discovery` 在 1440×900 下仍需横向滚动**：该表格 8 列声明总宽 1605px，1440 视口下容器为 1138px。要消除滚动需削减约 467px，即隐藏「关键依据」「最近发现」等证据列或把列宽压到影响可读的程度；且 743–1280px 之间的视口无论如何都会触发滚动。当前「操作列 sticky + 内容横向滚动」已是项目既有模式（`RouterVisible`、`ActiveRiskIps` 同款），操作在任意宽度下都可触达，因此**保持现状不修改**，仅在需要彻底免滚动时再作为独立议题评估。

**P1-01 的连带取舍**：操作列固定 220px 后，`/policies/destination-targets` 在 1280×800 下会有一列（「状态」）移到横向滚动区内。修复前是「操作不可达」，「状态」可见；修复后是「操作始终可达」，「状态」需小幅横向滚动。二者不可兼得（8 列在 962px 内容器内无法以可读列宽全部铺开）。如更看重「状态」常驻可见，可考虑把状态列左移到「判定方式」之前，或压缩窗口/阈值列宽——这属于信息层级的产品取舍，未擅自改动。

## 9. 文案审查（2026-10-11 同日追加）

对三类区域做了逐条通读：主内容区域（页头标题/副标题、卡片标题、区块说明）、Alert 组件（102 处）、弹窗组件（Modal 25 处 + Drawer 3 处），共 155 处。判定标准取自 AI 写作特征清单（夸大意义、宣传式用语、三段式罗列、空洞抽象名词、否定式排比、破折号、表情符号、模糊归因等）。

### 9.1 审查结论：文案底子是好的

定向扫描结果支持这个判断，不需要大面积重写：

| 扫描项 | 结果 |
|--------|------|
| AI 高频词（赋能/助力/一站式/无缝/全面/高效/智能/精准/打造/彰显/至关重要/此外/值得一提……） | 0 命中 |
| 否定式排比（不仅……而且……／不是……而是……） | 0 命中 |
| 表情符号 | 0 命中（AGENTS 规范已被遵守） |
| 破折号 | 3 处，全部是时间段分隔（`10:00 — 11:00`），属正常排版用法，非 AI 修辞 |
| ≥40 字的长文案 | 仅 27 条，且全部是具体字段、阈值与服务名说明 |
| 弹窗组件文案 | 基本是表单标签与按钮，无空泛表述 |

需要保留的是本项目真正的语气：**用"X 不等于 Y"把证据边界说清楚**。例如「入队不等于送达」「识别记录不等于处置授权」「证据不足不能解释为恢复正常」「空结果不表示用户已经离线」。这些话看着像排比，实际是防止运维误读的硬性语义约束，不属于 AI 痕迹，本次一条未改。

### 9.2 实际修改（14 处）

问题集中在**页头副标题**：模板化的多项罗列，配上 `闭环`／`统一留痕`／`呈现`／`解耦后的` 这类不承载信息的抽象名词。

| 位置 | 改前 | 改后 |
|------|------|------|
| 风险案件 | 按案件完成分派、调查、复核、处置与审计闭环 | 按状态、负责人与校区筛选，批量分派或关闭案件 |
| 案件详情 | 风险、身份、证据、复核结论与处置动作统一留痕 | 查看风险依据、关联身份、证据与处置记录 |
| 访问分析／技术指纹 | 基于标准事件元数据呈现 L7 协议流向、终端指纹碰撞与访问对象排行 | 从标准事件查看 L7 协议流向、终端指纹碰撞与访问对象排行 |
| DPI 标准事件检索 | 按时间、源/目的 IP、L7 访问对象与协议快速检索解耦后的标准事件流 | 按时间、IP、访问对象与协议检索标准事件 |
| 认证与处置接入 | ……真实动作受硬门槛、冷却和熔断保护 | ……真实动作需通过策略与身份检查 |
| 校区与网络区域 | 维护单校多校区、楼宇、网络区域和接入设备映射 | 维护校区与楼宇、网络区域与接入点 |
| 采集诊断与节点性能 | 检查采集节点、标准事件、丢包与异常记录 | 查看采集节点状态、标准事件与异常记录 |
| 通知模板与通道 | 策略提醒的模板、发送通道与真实投递状态 | 策略提醒的模板、发送通道与投递状态 |
| 处置记录 | 查看策略执行、人工审批、处置动作与撤销记录 | 查看策略执行与处置动作，包含审批和撤销记录 |
| 白名单 | 按认证身份与地址维护动作豁免 | 按账号、IP、MAC 与网段维护动作豁免 |
| **黑名单** | 命中即进入准入处置的策略名单 | 提供命中事实，处置由策略触发条件决定 |
| 共享发现 · 链路与处置说明 | 默认观测；未验收能力保持阻断 | 默认仅观测；未验收的下线能力保持阻断 |
| 主动发现 | 默认关闭；仅探测明确指定范围 | 默认关闭；仅探测配置范围内的地址 |
| 桑基图标题 | DPI L7 协议与应用流量流向桑基拓扑 (Sankey Flow Topology) | DPI L7 协议与应用流量桑基图 |

**黑名单那条不只是文风问题**：原副标题「命中即进入准入处置」与它正下方的 Alert「命中后需要策略授权才产生动作」互相矛盾，会让运维误以为加黑就会自动处置。这次改成与 Alert 一致的表述，属于正确性修正。

另外两处收紧：共享发现 Alert 的去重（去掉"或处罚"重复的第二个"不代表"），以及账号会话预览 Alert 的三重免责合成一句。桑基图 tooltip 里的 `➔`（dingbat 箭头）换成标准 `→`。

除此之外，弹窗文案未发现需要改动之处。

### 9.3 未改动但需要你决策的一项

`src/pages/RisksPage.tsx` 与 `src/pages/ReviewPage.tsx` 及其 `RisksRoute`／`ReviewRoute` 已无任何引用：`router.tsx` 把 `/risks`、`/review` 都指向 `LegacyRedirect to="/cases"`。这两个页面里恰恰有最像模板的副标题（「单行展示风险摘要，点击 IP 查看设备、证据与事件详情。」）。它们是死代码，删除属于清理范畴而非文风调整，本次未动。

## 10. 复现方式

```bash
cd frontend
pnpm exec playwright test tests/e2e/all-pages-audit.spec.ts --workers=1 --reporter=list
```

规格会自动拉起 `VITE_ENABLE_MOCKS=true` 的开发服务器（`127.0.0.1:5175`，`--strictPort`），跑完后：

- 机器可读结果：`frontend/test-results/all-pages-audit-全页面遍历-<视口>-chromium/all-pages.json`
- 逐页全页截图：同目录 `shots/<路由>-<宽度>.png`（共 141 张）

回归既有套件：

```bash
cd frontend
pnpm exec playwright test tests/e2e/all-pages-audit.spec.ts tests/e2e/ui-audit.spec.ts tests/e2e/menu-repair.spec.ts tests/e2e/screenshots.spec.ts --workers=1
```
