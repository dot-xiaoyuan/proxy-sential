# 防代理策略表达与目录同步重设计

状态：设计稿（待评审）
关联：`docs/legacy-feature-gap-ncu.md`、`docs/frontend-design-system.md`
背景故障：2026-10-14 现场「新建设备配额策略」的产品与用户组下拉同时为空。

## 1. 现场结论（实测）

### 1.1 下拉为空的直接原因（已修复）

| 事实 | 证据 |
| --- | --- |
| `product_catalog` 有 29 条可用产品（source `ncu-srun4k`） | `select count(*) ... where active` = 29 |
| `srun4k_group_catalog` 有 34 个用户组（source `ncu-srun4k:identity-observed`） | `select count(*)` = 34 |
| 桥接运行版本为 0 | `identity_bridge_runtime.active_config_version = 0`，`snapshot_state = failed` |
| 目录接口因此回退到占位 source | `fourKDirectorySource` 判定"非托管" → `srun-office`，该 source 下产品 0 条、组 0 条 |

即：**目录数据是齐的，接口查错了地方**。修复见提交 `ee3868bb`（已配置桥接优先于运行版本号；空列表必须点名 source）。

### 1.2 版本为什么卡在 0（现场链路的真实脆弱点）

桥接只有在**一次身份快照成功提交之后**才把活动版本提升（`cmd/legacy-4k-identity-bridge/main.go` 在快照成功分支才赋值），而现场快照连续失败：

```
snapshot_consecutive_failures: 7
last_error_type: online_inventory_changed / calibration_failed
online_members: 0
```

连锁后果：

1. 版本停在 0 → `catalogSyncer.syncOnce` 直接返回（`if host == "" || version < 1`），**产品目录同步被跳过**（`catalog_products: 0`，`last_catalog_at: null`）；
2. 版本停在 0 → 目录接口的 source 解析降级 → 表单空；
3. 版本停在 0 → 托管作用域的用户组快照也不写（`srun4k_integration.go` 的 `active_config_version>0` 条件）。

**结论：把"目录"绑在"两万多条在线身份快照"的成败上，是当前设计最大的问题。** 目录与在线状态的变化频率差几个数量级，不该共用一条会卡住的流水线。

## 2. 用户组现在是怎样同步过来的

现场存在三条互不相同的链路，只有第一条在跑：

| # | 链路 | 写入内容 | 现场状态 |
| --- | --- | --- | --- |
| 1 | 身份快照 → `refreshIdentityGroupCatalog` | 只有 `group_id`；`name` 空、无父子关系；source = `<source>:identity-observed` | **在跑**，34 条 |
| 2 | 4K 北向 `srunapi.Groups()` → `commitSRunGroups` | `group_id` + **`name`** + **`parent_id`** + **`path`**（完整树） | **从未跑**：`srun4k_integrations` 是空表 |
| 3 | 桥接读取目录 Redis（`list:products` / `list:control` / `hash:control:*`） | 只有产品与管控策略，**不含用户组** | 版本为 0，跳过 |

仓库中实际访问的 Redis 键只有：`list:products`、`list:control`、`list:products:control:<id>`、`hash:control:<id>`、`hash:products:<id>`（目录）与 `list:rad_online`、`hash:rad_online:<id>`、`list:antiproxy:...`（身份）。**没有任何用户组相关的键**——所以"组名"不可能从当前已接入的 Redis 侧补齐，只能来自 4K 北向接口。

所以现场"有 ID、没名称、没层级"不是 bug，而是**只有链路 1 在跑**。

### 2.1 北向接口实测（2026-10-14，从 184 只读探测）

用旧系统遗留的北向配置（`interface.northbound`：`https://222.204.3.227:8001`、app_id/app_secret）从 184 实测：

| 探测 | 结果 |
| --- | --- |
| `POST /api/v2/auth/get-access-token` | `code=0`，拿到 471 字符 token —— **凭据可用** |
| `POST /api/v2/base/get-online-total` | `{"code":0,…,"data":{"online_total":14569}}` —— token 有效 |
| `GET /api/v2/groups?page=1&per-page=100` | `code=0`，**88 个用户组且全部带中文名**：`{"id":208,"name":"访客"}`、`{"id":209,"name":"教职工"}`、`{"id":211,"name":"学生"}`、`{"id":212,"name":"学生宿舍辅导员"}` …… |
| ID 对照 | 北向返回的 `208/209/211/212/213…` 与 `srun4k_group_catalog` 里仅有编号的那批**完全对得上** |
| `per-page=500` | `code=10206`（4K 限制每页 ≤100） |
| `GET /api/v2/groups/tree`、`/api/v2/groups/detail` | `404` —— 该版本**没有层级接口** |
| 88 条中的 `pid` / `path` 字段 | **0 条**（`/api/v2/groups` 返回扁平列表） |

结论（修正原先的推测）：

- **名称可以拿到，而且现成可用**：只要把这份组目录同步进 `srun4k_group_catalog`，"组 208"就会变成"访客"。
- **层级当前拿不到**：这台 4K（`version: v1.5.7`）的 `/api/v2/groups` 不返回 `pid`/`path`，也没有 tree/detail 接口。前端已按 `parent_id` 渲染树的实现会**自动生效**——一旦有层级数据就直接显示层级，没有时就是扁平命名列表。

### 2.2 为什么现在没能同步（配置缺口）

`srunapi` 客户端由**原生配置文件**驱动（`PROXY_SENTINEL_NATIVE_ACTIONS_CONFIG`，`native_config.go`：`endpoint` + `app_id` + `app_secret` + …）。184 上该变量未设置、也没有对应文件，`srun4k_integrations` 与 `enforcement_connectors` 里都没有 4K 接入。因此链路 2 无从启动。

注意：该配置文件同时承载**下线动作**能力（native actions），所以配置它不只是"拿目录名"，而是接通处置通道，需要现场按授权流程单独决策与验收。

**最小可行路径**：新增一条只用于目录读取的北向凭据配置（或允许 4K 接入仅配置北向端点），配一个独立的"同步用户组目录"动作；该动作只调用 `srunapi.Groups()` 并全量替换 `srun4k_group_catalog` 的命名目录，不触发身份轮询、不启用任何处置动作。


## 3. 目录同步的正确设计

### 3.1 原则

- **目录与在线状态解耦**：产品目录和用户组树是"配置事实"，变更以天/周计；在线身份是"运行时事实"，每分钟都在变。两者不应共用状态机、不应互相阻塞。
- **一次同步、按需刷新**：目录同步是幂等全量替换（已有 `commitSRunGroups`/`commitSRunGroupsScoped` 的形态），可以手动触发、可以定时（如 6 小时）、可以在检测到变更时触发，但绝不依赖在线快照成功。
- **独立的同步状态**：目录同步要有自己的 `state / last_success_at / last_error_type`，供页面直接显示，而不是复用 `active_config_version`。

### 3.2 目标形态

```
4K 北向 API (srunapi.Groups / products)
        │  一次性全量拉取（幂等）
        ▼
srun4k_group_catalog(source, group_id, name, parent_id, path, active, observed_at)
product_catalog    (source, product_id, name, active, snapshot_id)
        │  只读、极廉价
        ▼
GET /integrations/4k-directory  →  表单选择器
```

要点：

1. **目录同步入口独立**：`POST /integrations/4k-directory/sync`（新），或复用现有 4K 同步但**去掉 `active_config_version>0` 门控**，只要求北向接入已配置。
2. **桥接不再承担组目录**：桥接的职责是身份与事件；组树来自北向 API。桥接的目录 Redis 读取保持现状。
3. **命名目录与观测目录分级**：北向写入的命名目录优先级高于身份观测到的 ID 目录（当前读取已按"有名优先"合并）。当两者都有时，展示名称与层级。
4. **同步状态可见**：目录页展示"上次同步时间 / 来源 / 条目数 / 最近错误"，空目录时给出可点击的同步入口。

### 3.3 兼容与降级

- 未配置北向接入时：仍可用身份观测到的 ID 目录（现状），但**界面必须说明"仅观测到 ID，配置 4K 北向接入可获取名称与层级"**。
- 目录为空时：不再渲染空白下拉，而是明确说明 + 同步入口（见 4.3）。

## 4. 「新建/编辑策略」表单重设计

### 4.1 现状问题

1. **强制三步 + 整屏滚动**：手机上一个策略要翻三屏；但真正的决策只有"对谁 / 什么算违规 / 怎么处理"三问。
2. **匹配维度平铺且语义混杂**：产品（套餐）、用户组（组织）、VLAN、账号同权重并列，前两者才是主维度，后两者是例外手段。
3. **触发条件用四个"或者"横排**：窄屏折行后难以阅读，且看不出"或"的语义。
4. **动作是三张互不相关的卡片**：而真实策略几乎都是"先通知、再升级"的链式结构，卡片形态表达不出升级关系。
5. **目录状态不可见**：空/失败/加载都是空白下拉。
6. **保存前没有可读回执**：管理员无法在保存前确认自己配了什么。

### 4.2 设计目标

- 一屏完成常见策略（学生/教职工套餐 + 设备数阈值 + 通知+下线）。
- 任何时候都能用一句话读懂当前配置。
- 复杂能力（多条件、多级动作、时段、高级匹配）可展开但不干扰。

### 4.3 目标信息架构（单页分区，取消强制分步）

```
┌ 新建设备配额策略 ──────────────────────────────┐
│ 策略摘要  教职工 · 全部设备数 > 2 → 通知，2 次后下线 │  ← 实时回显，只读
├──────────────────────────────────────────────┤
│ ① 名称与运行模式                                │
│    策略名称 [____________]   运行模式 [真实执行 ▾] │
├──────────────────────────────────────────────┤
│ ② 对谁生效（主维度）                            │
│    产品   [TreeSelect 教职工 ×] [学生包月40 ×]    │
│    用户组 [TreeSelect 信息工程学院 ×]             │
│    ▸ 高级匹配（可选）  VLAN / 账号 / 校区          │
├──────────────────────────────────────────────┤
│ ③ 什么算违规                                    │
│    ☑ 全部设备数 > [ 2 ]                          │
│    ☐ 电脑数量   > [  ]   ☐ 移动设备数 > [  ]      │
│    ☐ 发现路由器 > [ 0 ]   （命中任一即触发）        │
├──────────────────────────────────────────────┤
│ ④ 怎么处理（升级链）                             │
│    首次命中 → 通知[模板 ▾]                         │
│    每 [2] 次通知 → 强制下线                        │
│    [+ 添加一级动作]                              │
├──────────────────────────────────────────────┤
│                        [取消]  [保存并保持停用]     │
└──────────────────────────────────────────────┘
```

### 4.4 关键交互

1. **策略摘要行（新增）**：由当前表单值实时生成一句中文，放在标题下。它同时是"配置是否正确"的即时校验，也是保存前回执的雏形。
2. **主维度与高级匹配分离**：产品、用户组常驻；VLAN、账号、校区收进 `<details>`（已实现）。
3. **用户组用 `TreeSelect`**：按 `parent_id` 还原层级，`label` 优先 `name`，无名称时显示 `组 208`（次要文字给 ID），让"只有 ID"这件事一眼可见而不是伪装成正常。
4. **条件改为勾选行 + 数值**：每行一个条件，默认只勾第一行；"命中任一即触发"以说明文字呈现，取代四个"或者"。
5. **动作改为升级链**：一级一行，行内选择动作类型与参数；"依赖前置动作 + 次数"直接对应后端 `Stage.DependsOn` + `Stage.MinEpisodes`，不再需要管理员理解 `depends_on`。
6. **空态可操作**：目录为空或加载失败时，选择器下方显示：
   - 失败：`4K 目录读取失败：<原因>` + [重试]
   - 空：`来源 ncu-srun4k 没有可用用户组目录` + [去同步 4K 目录]（链接到 `/settings/actions`）
7. **保存语义**：主按钮为「保存并保持停用」（与后端"新建默认停用"一致），保存成功后提示"策略已保存，处于停用状态，可在列表中开启"。

### 4.5 后端映射（不改契约）

| 表单元素 | `policy.Definition` |
| --- | --- |
| 产品 | `scope.products` |
| 用户组 | `scope.groups` |
| VLAN / 账号 / 校区 | `scope.vlans` / `scope.accounts` / `scope.campuses` |
| 条件行 | `limits.total` / `pc` / `mobile` / `router` |
| 升级链第 i 级 | `stages[i]`；上一级 = `stages[i].depends_on = [前一级 action]` |
| "每 N 次" | `stages[i].min_episodes` |
| 动作类型 | `notify` / `disconnect` / `rate_limit` / `disable_account` |
| 运行模式 | `mode`（observe / manual / automatic） |

现有 `ActionModel = dpi-strategy/v1` 已支持依赖与滚动升级，前端只需把"链"渲染出来，无需新增字段。

### 4.6 分阶段落地

1. **P0（小改动，先可用）**：空态可操作 + 用户组 `TreeSelect` + 策略摘要行；保留现有三步。
2. **P1**：合并为单页分区，条件行化，动作升级链化。
3. **P2**：目录同步独立入口与状态面板（第 3 节），让"只同步一次"成为现实。

## 5. 验收标准

- 目录接口在桥接版本为 0 时仍返回正确 source 的产品与用户组（已由 `TestFourKDirectoryReturnsCatalogWhileBridgeVersionIsZero` 覆盖）。
- 空列表必须携带可读原因与可点击的下一步，不允许出现无解释的空白下拉。
- 组树同步后，选择器展示中文名称与层级；仅有 ID 时必须显式提示"仅观测到 ID"。
- 三视口（390×844 / 743×774 / 1280×1440）下：一屏内可完成常见策略；无横向溢出；按钮不竖排；主操作始终在视口内。
- 保存前可见一句中文摘要；保存后明确告知策略处于停用状态。
