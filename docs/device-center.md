# 统一设备中心

## 入口与权限

`/devices` 为设备中心，`tab=terminal|network|iot`。`aux=records|link|history` 进入发现线索、仅链路线索、历史设备。`aux=profiles` 是档案追溯辅助视图。共享发现默认当前共享，旧 `tab=devices` 转入网络设备；仅有 `cases:read` 的账号保留档案追溯权限。

网络设备仍按路由身份聚合，MAC 合并要求采集范围和 VLAN 一致；没有范围的观察保留身份，不按 IP 强行合并。`/devices/network/:assessmentId` 是统一网络设备链接，旧 `/discovery/routers/:assessmentId` 保留查询参数和返回上下文后重定向。共享上下文接口独立要求 `cases:read`，按 `source_assessment_id` 精确关联，多个采集范围档案不自动选取。

## 地址与展示

终端列表的 `address_state=current|link|history|all` 在后端分页前生效。有效租约排除后续释放或转移；认证会话使用当前会话及投影源的新鲜度，并设置 90 分钟的会话确认窗口。返回 `current_addresses`、`current_ip`、`historical_ip` 和 `device_url`。IPv4 优先，只有 IPv6 时直接展示 IPv6。名字和 MAC 为辅助字段；历史地址不冒充当前地址。

发现列表同样支持 `address_state`，返回的主地址只来自有效观测。设备链接可用 `?tab=iot&device=ID`，单个设备通过 `/discovery/devices/ID` 读取。

## 变化摘要与原始证据

`GET /device-history/{kind}/{id}?limit=20&offset=0` 返回连续变化段，含 `first_seen`、`last_seen`、`count`、有效内容和 `as_of`。后续页沿用 `as_of`；加入 `group` 查询指定摘要的原始记录，每页最多 100 条。分组、总数和分页在同一 SQL 快照完成。

支持 router、router_evidence、profile、shared、discovery、endpoint_discovery、endpoint、access。profile/shared 需要 `cases:read`，其余需要 `identity:read`。按身份、采集范围、协议流的连续状态压缩；时间、事件标识、刷新和租约续期不构成内容变化。IP/MAC、账号、类型、能力、判定、分数、冲突、撤回及规则变化保留，A→B→A 保留三段。原表不删改。

旧详情的 history 数组保留为空的兼容字段，新界面按需读取历史接口。路由详情的旧 evidence 字段最多保留 50 条预览，新界面使用分页证据摘要。

## 迁移与验收

新增 `104_device_center_current_address_indexes.sql` 两个时间索引，支持有效租约和近期认证会话查询，不创建身份或改变策略。序号 100–103 为主工作区其他未发布功能预留，本分支不携带这些改动。

针对性 PostgreSQL 回放覆盖重复压缩、跨页计数、A→B→A、撤回、规则变化、IP 复用、地址到期、释放、双栈及 IPv6-only。前端自动检查三个规定视口的截图、DOM 样式、主地址格式、移动卡片、旧链接和原始记录分页。登录后的现场业务验收需要有效登录会话，静态资源 200 不代替该验收。
