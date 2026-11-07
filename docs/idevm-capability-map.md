# IDevM 接口 × Proxy Sentinel 能力对照表

本表把 idevm 后端实际注册的 HTTP 接口按模块逐一对照 Proxy Sentinel 现有能力，用于判断“idevm 还有什么值得接、什么不该接”。

TL;DR：204 条里 34 条不适用、11 条已重合、55 条部分重合、104 条缺口；缺口集中在**登记运营流程**和**管理配置**，不在识别本身。

## 口径

- 基线：idevm 后端 `idevm-204` worktree（develop `7932612`），2026-11-07 解析。
- 接口清单由 `idevm-api-source/router/*.go` 的路由注册解析得到，共 **204 条有效接口**；另有 7 条被注释保留（`adminMgr.PUT("rest")`、`deviceMgr.PUT("field-update")`、`deviceMgr.DELETE("offline")`、`find.PUT("dhcp/:id/register")`、`log.POST("del-manager-login")`、`products.POST("disable-product")`、`products.POST("enable-product")`），不计入。此前口头说的 211 是包含这 7 条的粗计。
- Proxy Sentinel 能力取自本仓库 `internal/controlplane` 的实际路由与 `docs/current-work.md` 的验收记录；不把“计划要做”算作已有能力。
- 判定四级：**重合**＝已有等价能力；**部分重合**＝语义不同或只有只读/局部覆盖；**缺口**＝完全没有；**不适用**＝属 RADIUS/AAA、计费套餐、访客、实际下发动作或明确不做范围。

## 汇总

| 判定 | 接口数 | 占比 |
| --- | ---: | ---: |
| 重合 | 11 | 5% |
| 部分重合 | 55 | 27% |
| 缺口 | 104 | 51% |
| 不适用 | 34 | 17% |
| **合计** | **204** | 100% |

| 模块 | 接口数 | 重合 | 部分重合 | 缺口 | 不适用 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 发现与在线 | 1 | 0 | 1 | 0 | 0 |
| 设备列表 | 2 | 1 | 0 | 1 | 0 |
| 在线与详情 | 9 | 2 | 4 | 0 | 3 |
| 登记与审核 | 14 | 1 | 2 | 11 | 0 |
| 登记模板 | 6 | 0 | 0 | 6 | 0 |
| 批量处理 | 8 | 0 | 0 | 8 | 0 |
| 组织机构 | 6 | 0 | 2 | 4 | 0 |
| 位置管理 | 6 | 0 | 2 | 4 | 0 |
| 用户组 | 9 | 0 | 1 | 8 | 0 |
| 自助服务 | 12 | 2 | 5 | 5 | 0 |
| 角色权限 | 5 | 0 | 1 | 4 | 0 |
| 管理员 | 8 | 0 | 0 | 8 | 0 |
| IP 管理 | 7 | 0 | 0 | 7 | 0 |
| 产品与套餐 | 6 | 0 | 3 | 0 | 3 |
| 准入策略 | 21 | 0 | 3 | 0 | 18 |
| 域名策略 | 4 | 0 | 1 | 0 | 3 |
| 在线会话 | 5 | 0 | 4 | 0 | 1 |
| 访客 | 6 | 0 | 0 | 0 | 6 |
| 日志 | 9 | 1 | 6 | 2 | 0 |
| 系统设置 | 26 | 0 | 10 | 16 | 0 |
| 网络探测 | 1 | 0 | 1 | 0 | 0 |
| 单点登录 | 5 | 0 | 2 | 3 | 0 |
| WebAuthn | 5 | 0 | 0 | 5 | 0 |
| 公共/账号 | 11 | 0 | 2 | 9 | 0 |
| 登录与权限 | 5 | 2 | 2 | 1 | 0 |
| 系统参数 | 5 | 0 | 3 | 2 | 0 |
| 概览 | 2 | 2 | 0 | 0 | 0 |
| **合计** | **204** | **11** | **55** | **104** | **34** |

## 明细

| # | 模块 | 接口 | 功能 | Proxy Sentinel 现状 | 判定 |
| ---: | --- | --- | --- | --- | --- |
| 1 | 发现与在线 | `GET /v3/deviceMgr/find/dhcp` | 按 DHCP 数据查未登记设备 | 被动发现（DHCP 事件来自镜像协议，不是租约库） | 部分重合 |
| 2 | 设备列表 | `POST /v3/device/edit-device-available` | 修改设备可用/准入状态 | 无；本系统只记录，不下发准入 | 缺口 |
| 3 | 设备列表 | `GET /v3/device/list` | 设备台账列表 | /device-inventory 设备中心列表 | 重合 |
| 4 | 在线与详情 | `DELETE /v3/deviceMgr/device` | 删除已登记设备 | 登记台账只有更新，无删除 | 部分重合 |
| 5 | 在线与详情 | `GET /v3/deviceMgr/device` | 已登记设备详情 | /endpoints/registrations + 端点详情 | 重合 |
| 6 | 在线与详情 | `PUT /v3/deviceMgr/device` | 编辑已登记设备 | /endpoints/{id}/registration（upsert） | 重合 |
| 7 | 在线与详情 | `GET /v3/deviceMgr/field` | RADIUS 可用字段字典 | 无（AAA 域） | 不适用 |
| 8 | 在线与详情 | `GET /v3/deviceMgr/nas/list` | NAS 接入设备列表 | 无（AAA 域） | 不适用 |
| 9 | 在线与详情 | `DELETE /v3/deviceMgr/online` | 强制在线设备下线 | 无；观察期明确禁止下发下线 | 不适用 |
| 10 | 在线与详情 | `GET /v3/deviceMgr/online` | 在线设备列表 | 身份在线会话（只读） | 部分重合 |
| 11 | 在线与详情 | `GET /v3/deviceMgr/online-list` | RADIUS 在线列表 | 身份在线会话（只读） | 部分重合 |
| 12 | 在线与详情 | `GET /v3/deviceMgr/product` | 设备当前产品/套餐 | product-policy 快照（只读） | 部分重合 |
| 13 | 登记与审核 | `POST /v3/deviceMgr/register/audit-device` | 审核设备登记 | 无审核流；登记即时生效 | 缺口 |
| 14 | 登记与审核 | `GET /v3/deviceMgr/register/batch-log` | 批量登记处理记录 | 无 | 缺口 |
| 15 | 登记与审核 | `POST /v3/deviceMgr/register/device-check` | 提交审核 | 无审核流 | 缺口 |
| 16 | 登记与审核 | `DELETE /v3/deviceMgr/register/device-check-cancel` | 取消审核 | 无审核流 | 缺口 |
| 17 | 登记与审核 | `GET /v3/deviceMgr/register/device-check-detail` | 审核详情 | 无审核流 | 缺口 |
| 18 | 登记与审核 | `GET /v3/deviceMgr/register/device-check-list` | 待审列表 | 无审核流 | 缺口 |
| 19 | 登记与审核 | `GET /v3/deviceMgr/register/device-check-num` | 待审数量 | 无审核流 | 缺口 |
| 20 | 登记与审核 | `GET /v3/deviceMgr/register/device-record` | 登记记录 | 登记台账列表（不含自助来源） | 部分重合 |
| 21 | 登记与审核 | `POST /v3/deviceMgr/register/device-register` | 自助登记提交 | 无自助门户 | 缺口 |
| 22 | 登记与审核 | `POST /v3/deviceMgr/register/dhcp` | 查询 DHCP 待登记设备 | 发现→登记入口（登记台账） | 部分重合 |
| 23 | 登记与审核 | `POST /v3/deviceMgr/register/single` | 单个设备登记 | /endpoints/{id}/registration 新增 | 重合 |
| 24 | 登记与审核 | `GET /v3/deviceMgr/register/template` | 下载批量登记模板 | 无 | 缺口 |
| 25 | 登记与审核 | `POST /v3/deviceMgr/register/template` | 批量导入登记 | 无 | 缺口 |
| 26 | 登记与审核 | `GET /v3/deviceMgr/register/ws-device` | 登记状态 WebSocket 推送 | 无；页面走轮询/SSE | 缺口 |
| 27 | 登记模板 | `POST /v3/template/add` | 新增模板 | 无 | 缺口 |
| 28 | 登记模板 | `DELETE /v3/template/delete` | 删除模板 | 无 | 缺口 |
| 29 | 登记模板 | `GET /v3/template/detail` | 模板详情 | 无 | 缺口 |
| 30 | 登记模板 | `GET /v3/template/list` | 登记模板列表 | 无类别化模板 | 缺口 |
| 31 | 登记模板 | `GET /v3/template/name-list` | 模板名称列表 | 无 | 缺口 |
| 32 | 登记模板 | `POST /v3/template/update` | 修改模板 | 无 | 缺口 |
| 33 | 批量处理 | `GET /v3/batch/base-fields` | 批量可改字段 | 无批量作业 | 缺口 |
| 34 | 批量处理 | `POST /v3/batch/change-person` | 批量改责任人 | 无批量作业 | 缺口 |
| 35 | 批量处理 | `POST /v3/batch/change-product` | 批量改产品 | 无批量作业 | 缺口 |
| 36 | 批量处理 | `POST /v3/batch/change-state` | 批量改状态 | 无批量作业 | 缺口 |
| 37 | 批量处理 | `POST /v3/batch/delete` | 批量删除 | 无批量作业 | 缺口 |
| 38 | 批量处理 | `POST /v3/batch/remove` | 批量解除绑定 | 无批量作业 | 缺口 |
| 39 | 批量处理 | `GET /v3/batch/template` | 批量操作模板下载 | 无批量作业 | 缺口 |
| 40 | 批量处理 | `POST /v3/batch/update` | 批量更新字段 | 无批量作业 | 缺口 |
| 41 | 组织机构 | `DELETE /v3/dept` | 删除部门 | 无 | 缺口 |
| 42 | 组织机构 | `GET /v3/dept` | 部门树 | 组织/部门来自身份与组织权限（只读） | 部分重合 |
| 43 | 组织机构 | `POST /v3/dept` | 新增部门 | 无部门维护接口 | 缺口 |
| 44 | 组织机构 | `PUT /v3/dept` | 修改部门 | 无 | 缺口 |
| 45 | 组织机构 | `POST /v3/dept/import` | 导入部门 | 无 | 缺口 |
| 46 | 组织机构 | `GET /v3/dept/list` | 部门下拉 | 组织权限部门集合（只读） | 部分重合 |
| 47 | 位置管理 | `POST /v3/location/add` | 新增位置 | 无位置主数据管理 | 缺口 |
| 48 | 位置管理 | `GET /v3/location/child` | 位置子节点 | 位置维度统计（近似） | 部分重合 |
| 49 | 位置管理 | `DELETE /v3/location/delete` | 删除位置 | 无 | 缺口 |
| 50 | 位置管理 | `GET /v3/location/list` | 位置树 | /device-inventory/position（只读统计，非树） | 部分重合 |
| 51 | 位置管理 | `POST /v3/location/sort` | 位置排序 | 无 | 缺口 |
| 52 | 位置管理 | `POST /v3/location/update` | 修改位置 | 无 | 缺口 |
| 53 | 用户组 | `POST /v3/groups/add` | 新增用户组 | 无用户组模型 | 缺口 |
| 54 | 用户组 | `DELETE /v3/groups/bind` | 解绑组 | 无 | 缺口 |
| 55 | 用户组 | `GET /v3/groups/bind` | 查询组绑定 | 无 | 缺口 |
| 56 | 用户组 | `POST /v3/groups/bind` | 绑定组 | 无 | 缺口 |
| 57 | 用户组 | `POST /v3/groups/bind-product` | 用户组绑定产品 | 无（只读快照） | 缺口 |
| 58 | 用户组 | `POST /v3/groups/delete-group` | 删除用户组 | 无 | 缺口 |
| 59 | 用户组 | `POST /v3/groups/edit` | 修改用户组 | 无 | 缺口 |
| 60 | 用户组 | `GET /v3/groups/get-product` | 组可绑定产品 | product-policy 目录（只读） | 部分重合 |
| 61 | 用户组 | `GET /v3/groups/other` | 其他用户组 | 无 | 缺口 |
| 62 | 自助服务 | `POST /v3/selfService/device/change-available` | 自助改设备可用状态 | 无 | 缺口 |
| 63 | 自助服务 | `DELETE /v3/selfService/device/delete` | 自助删除设备 | 无 | 缺口 |
| 64 | 自助服务 | `GET /v3/selfService/device/detail` | 我的设备详情 | 无 | 缺口 |
| 65 | 自助服务 | `GET /v3/selfService/device/list` | 我的设备列表 | 无自助门户 | 缺口 |
| 66 | 自助服务 | `GET /v3/selfService/log/auth` | 自助认证日志 | 认证事件只读查询 | 部分重合 |
| 67 | 自助服务 | `GET /v3/selfService/log/detail` | 自助在线明细 | 身份在线会话（只读） | 部分重合 |
| 68 | 自助服务 | `GET /v3/selfService/log/operating` | 自助操作日志 | 管理侧 audit-logs（非自助视图） | 部分重合 |
| 69 | 自助服务 | `GET /v3/selfService/user/action` | 自助登录方式 | /session 登录方式 | 部分重合 |
| 70 | 自助服务 | `GET /v3/selfService/user/info` | 自助账号信息 | /session 用户信息 | 部分重合 |
| 71 | 自助服务 | `POST /v3/selfService/user/login` | 自助用户登录 | /auth/login | 重合 |
| 72 | 自助服务 | `DELETE /v3/selfService/user/logout` | 自助登出 | /auth/logout | 重合 |
| 73 | 自助服务 | `GET /v3/selfService/user/names` | 用户名列表 | 无 | 缺口 |
| 74 | 角色权限 | `DELETE /v3/role` | 删除角色 | 无 | 缺口 |
| 75 | 角色权限 | `GET /v3/role` | 角色列表 | 本地固定角色（auth 文件） | 部分重合 |
| 76 | 角色权限 | `POST /v3/role` | 新增角色 | 无角色管理 API | 缺口 |
| 77 | 角色权限 | `PUT /v3/role` | 修改角色 | 无 | 缺口 |
| 78 | 角色权限 | `GET /v3/role/detail` | 角色详情 | 无 | 缺口 |
| 79 | 管理员 | `DELETE /v3/adminMgr/admin` | 删除管理员 | 无 | 缺口 |
| 80 | 管理员 | `GET /v3/adminMgr/admin` | 管理员列表 | 无管理员管理 API | 缺口 |
| 81 | 管理员 | `POST /v3/adminMgr/admin` | 新增管理员 | 无 | 缺口 |
| 82 | 管理员 | `PUT /v3/adminMgr/admin` | 修改管理员 | 无 | 缺口 |
| 83 | 管理员 | `GET /v3/adminMgr/admin/detail` | 管理员详情 | 无 | 缺口 |
| 84 | 管理员 | `GET /v3/adminMgr/admin/editable` | 可分配权限范围 | 无 | 缺口 |
| 85 | 管理员 | `PUT /v3/adminMgr/admin/password` | 重置管理员口令 | 无（auth 文件手工维护） | 缺口 |
| 86 | 管理员 | `GET /v3/adminMgr/all` | 管理员下拉 | 无 | 缺口 |
| 87 | IP 管理 | `GET /v3/ipMgr/check` | IP 占用检查 | 无 | 缺口 |
| 88 | IP 管理 | `DELETE /v3/ipMgr/pool` | 删除 IP 池 | 无 | 缺口 |
| 89 | IP 管理 | `GET /v3/ipMgr/pool` | IP 池列表 | 无 IP 池管理 | 缺口 |
| 90 | IP 管理 | `POST /v3/ipMgr/pool` | 新增 IP 池 | 无 | 缺口 |
| 91 | IP 管理 | `PUT /v3/ipMgr/pool` | 修改 IP 池 | 无 | 缺口 |
| 92 | IP 管理 | `GET /v3/ipMgr/pool/detail` | IP 池详情 | 无 | 缺口 |
| 93 | IP 管理 | `GET /v3/ipMgr/unused` | 未使用地址 | 无 | 缺口 |
| 94 | 产品与套餐 | `GET /v3/productMgr/all-groups` | 产品组 | product-policy 目录（只读） | 部分重合 |
| 95 | 产品与套餐 | `GET /v3/productMgr/list` | 产品列表 | product-policy 目录（只读快照） | 部分重合 |
| 96 | 产品与套餐 | `DELETE /v3/productMgr/product` | 删除产品 | 不写产品体系 | 不适用 |
| 97 | 产品与套餐 | `GET /v3/productMgr/product` | 查询产品 | product-policy 目录（只读） | 部分重合 |
| 98 | 产品与套餐 | `POST /v3/productMgr/product` | 新增产品 | 不写产品/计费体系（属 4K） | 不适用 |
| 99 | 产品与套餐 | `PUT /v3/productMgr/product` | 修改产品 | 不写产品体系 | 不适用 |
| 100 | 准入策略 | `POST /v3/internet/batch-change-product` | 批量换产品 | 不适用 | 不适用 |
| 101 | 准入策略 | `POST /v3/internet/control-edit-sync` | 策略编辑同步 | 不适用 | 不适用 |
| 102 | 准入策略 | `POST /v3/internet/custom-add` | 新增自定义属性 | 无 RADIUS | 不适用 |
| 103 | 准入策略 | `POST /v3/internet/custom-delete` | 删除自定义属性 | 无 RADIUS | 不适用 |
| 104 | 准入策略 | `POST /v3/internet/custom-edit` | 修改自定义属性 | 无 RADIUS | 不适用 |
| 105 | 准入策略 | `GET /v3/internet/custom-list` | 自定义 RADIUS 属性列表 | 无 RADIUS | 不适用 |
| 106 | 准入策略 | `GET /v3/internet/domain` | 准入域名列表 | 应用/域名库（只读，非策略） | 部分重合 |
| 107 | 准入策略 | `POST /v3/internet/domain-add` | 新增准入域名 | 不适用 | 不适用 |
| 108 | 准入策略 | `POST /v3/internet/domain-delete` | 删除准入域名 | 不适用 | 不适用 |
| 109 | 准入策略 | `POST /v3/internet/domain-edit` | 修改准入域名 | 不适用 | 不适用 |
| 110 | 准入策略 | `GET /v3/internet/download` | 控制策略 CSV 导出 | 有异步 CSV 导出能力（内容不同） | 部分重合 |
| 111 | 准入策略 | `POST /v3/internet/edit` | 修改控制策略 | 无策略下发；本系统只记录 | 不适用 |
| 112 | 准入策略 | `POST /v3/internet/radius-add` | 新增 RADIUS 属性 | 无 RADIUS | 不适用 |
| 113 | 准入策略 | `POST /v3/internet/radius-delete` | 删除 RADIUS 属性 | 无 RADIUS | 不适用 |
| 114 | 准入策略 | `POST /v3/internet/radius-edit` | 修改 RADIUS 属性 | 无 RADIUS | 不适用 |
| 115 | 准入策略 | `GET /v3/internet/radius-get-vendor` | RADIUS 厂商字典 | 无 RADIUS | 不适用 |
| 116 | 准入策略 | `GET /v3/internet/radius-list` | RADIUS 模板列表 | 无 RADIUS | 不适用 |
| 117 | 准入策略 | `GET /v3/internet/radius-radio-list-value` | RADIUS 可选值 | 无 RADIUS | 不适用 |
| 118 | 准入策略 | `GET /v3/internet/radius-template` | RADIUS 模板详情 | 无 RADIUS | 不适用 |
| 119 | 准入策略 | `POST /v3/internet/radius-template-edit` | 编辑 RADIUS 模板 | 无 RADIUS | 不适用 |
| 120 | 准入策略 | `GET /v3/internet/search` | 准入控制策略查询 | product-policy 只读快照 | 部分重合 |
| 121 | 域名策略 | `POST /v3/domain/create` | 新增域名策略 | 无策略下发 | 不适用 |
| 122 | 域名策略 | `POST /v3/domain/delete` | 删除域名策略 | 无策略下发 | 不适用 |
| 123 | 域名策略 | `GET /v3/domain/search` | 域名策略查询 | /application-library 应用域名库（只读） | 部分重合 |
| 124 | 域名策略 | `POST /v3/domain/update` | 修改域名策略 | 无策略下发 | 不适用 |
| 125 | 在线会话 | `GET /v3/online` | 在线会话列表 | 身份在线会话（只读） | 部分重合 |
| 126 | 在线会话 | `GET /v3/online/count` | 在线数统计 | 在线身份计数（只读） | 部分重合 |
| 127 | 在线会话 | `POST /v3/online/drop` | 踢下线 | 无；观察期禁止执行 | 不适用 |
| 128 | 在线会话 | `GET /v3/online/equipment` | 按设备看在线 | 端点+会话关联（只读） | 部分重合 |
| 129 | 在线会话 | `GET /v3/online/search` | 在线检索 | 身份在线检索（只读） | 部分重合 |
| 130 | 访客 | `GET /v3/visitor/day-detail` | 访客当日明细 | 无 | 不适用 |
| 131 | 访客 | `GET /v3/visitor/in-visitor` | 来访人数统计 | 无 | 不适用 |
| 132 | 访客 | `GET /v3/visitor/list` | 访客名单 | 无 | 不适用 |
| 133 | 访客 | `GET /v3/visitor/out-visitor` | 出访记录 | 无 | 不适用 |
| 134 | 访客 | `GET /v3/visitor/search` | 访客查询 | 无访客体系 | 不适用 |
| 135 | 访客 | `GET /v3/visitor/top` | 访客使用量 TOP | 无 | 不适用 |
| 136 | 日志 | `GET /v3/log/auth` | 认证日志 | 认证/RADIUS 事件只读 | 部分重合 |
| 137 | 日志 | `GET /v3/log/auth/download` | 认证日志导出 | 异步导出（无认证日志） | 部分重合 |
| 138 | 日志 | `GET /v3/log/detail` | 在线明细日志 | 身份会话事件（只读） | 部分重合 |
| 139 | 日志 | `GET /v3/log/download` | 在线明细导出 | 异步 CSV 导出能力 | 部分重合 |
| 140 | 日志 | `GET /v3/log/manager-login` | 管理员登录日志 | audit-logs 登录审计 | 部分重合 |
| 141 | 日志 | `GET /v3/log/operating` | 操作日志 | /audit-logs | 重合 |
| 142 | 日志 | `GET /v3/log/overhead-household` | 超载用户日志 | 无 | 缺口 |
| 143 | 日志 | `GET /v3/log/overhead-household/download` | 超载用户日志导出 | 无 | 缺口 |
| 144 | 日志 | `GET /v3/log/system` | 系统日志 | /system/status、/ingest/diagnostics | 部分重合 |
| 145 | 系统设置 | `GET /v3/setting/dataCollect/dhcp` | DHCP 采集配置 | /ingest/status、/discovery/sources（只读） | 部分重合 |
| 146 | 系统设置 | `PUT /v3/setting/dataCollect/dhcp` | 保存 DHCP 采集配置 | 无写接口（配置在部署侧） | 缺口 |
| 147 | 系统设置 | `DELETE /v3/setting/deviceType` | 删除设备类别 | 无 | 缺口 |
| 148 | 系统设置 | `GET /v3/setting/deviceType` | 设备类别列表 | /discovery/types 是识别统计，不是可维护字典 | 部分重合 |
| 149 | 系统设置 | `POST /v3/setting/deviceType` | 新增设备类别 | 无类别字典 CRUD | 缺口 |
| 150 | 系统设置 | `PUT /v3/setting/deviceType` | 修改设备类别 | 无 | 缺口 |
| 151 | 系统设置 | `GET /v3/setting/deviceType/detail` | 设备类别详情 | 无字典维护 | 部分重合 |
| 152 | 系统设置 | `POST /v3/setting/deviceType/sort` | 类别排序 | 无 | 缺口 |
| 153 | 系统设置 | `DELETE /v3/setting/dpi` | 删除 DPI 数据 | 无 | 缺口 |
| 154 | 系统设置 | `GET /v3/setting/dpi` | DPI 数据列表 | /dpi/* 只读视图 | 部分重合 |
| 155 | 系统设置 | `POST /v3/setting/dpi` | 新增 DPI 数据 | 无 | 缺口 |
| 156 | 系统设置 | `PUT /v3/setting/dpi` | 修改 DPI 数据 | 无 | 缺口 |
| 157 | 系统设置 | `GET /v3/setting/ip-white-list` | IP 白名单（免认证准入） | /whitelist、/blacklist 为风险名单 | 部分重合 |
| 158 | 系统设置 | `PUT /v3/setting/ip-white-list` | 保存 IP 白名单 | /whitelist 写入（风险豁免，非准入） | 部分重合 |
| 159 | 系统设置 | `GET /v3/setting/mac-white-list` | MAC 白名单（免认证准入） | /whitelist 为风险豁免白名单，语义不同 | 部分重合 |
| 160 | 系统设置 | `PUT /v3/setting/mac-white-list` | 保存 MAC 白名单 | /whitelist 写入（风险豁免，非准入） | 部分重合 |
| 161 | 系统设置 | `GET /v3/setting/query` | 类别查询 | 识别统计（近似） | 部分重合 |
| 162 | 系统设置 | `GET /v3/setting/selfService/company` | 公司/站点信息 | 无 | 缺口 |
| 163 | 系统设置 | `GET /v3/setting/selfService/login/account` | 自助账号登录配置 | 无 | 缺口 |
| 164 | 系统设置 | `PUT /v3/setting/selfService/login/account` | 保存账号登录配置 | 无 | 缺口 |
| 165 | 系统设置 | `GET /v3/setting/selfService/login/mail` | 自助邮箱登录配置 | 无 | 缺口 |
| 166 | 系统设置 | `PUT /v3/setting/selfService/login/mail` | 保存邮箱配置 | 无 | 缺口 |
| 167 | 系统设置 | `GET /v3/setting/selfService/login/sms` | 自助短信登录配置 | 无 | 缺口 |
| 168 | 系统设置 | `PUT /v3/setting/selfService/login/sms` | 保存短信配置 | 无 | 缺口 |
| 169 | 系统设置 | `GET /v3/setting/selfService/login/srun4k` | 4K 对接参数 | 4K 集成参数（只读） | 部分重合 |
| 170 | 系统设置 | `PUT /v3/setting/selfService/login/srun4k` | 保存 4K 参数 | 无 | 缺口 |
| 171 | 网络探测 | `POST /v3/detect/ping` | 探测终端连通性 | /discovery/preview 等主动探测（不做扫描评估） | 部分重合 |
| 172 | 单点登录 | `GET /v3/sso/cas/action` | CAS 统一身份认证回调 | OIDC 已支持，CAS 未接 | 部分重合 |
| 173 | 单点登录 | `GET /v3/sso/dd/action` | 钉钉登录回调 | 无 | 缺口 |
| 174 | 单点登录 | `GET /v3/sso/dd/bit` | 钉钉定制登录 | 无 | 缺口 |
| 175 | 单点登录 | `GET /v3/sso/ids/action` | 金智 IDS 登录 | 无 | 缺口 |
| 176 | 单点登录 | `GET /v3/sso/login/url` | 生成单点登录地址 | /auth/oidc/start | 部分重合 |
| 177 | WebAuthn | `GET /v3/webauthn/backend/auth/begin` | WebAuthn 认证开始 | 无 | 缺口 |
| 178 | WebAuthn | `POST /v3/webauthn/backend/auth/finish` | WebAuthn 认证完成 | 无 | 缺口 |
| 179 | WebAuthn | `POST /v3/webauthn/backend/register/begin` | WebAuthn 注册开始 | 无 | 缺口 |
| 180 | WebAuthn | `POST /v3/webauthn/backend/register/finish` | WebAuthn 注册完成 | 无 | 缺口 |
| 181 | WebAuthn | `GET /v3/webauthn/backend/register/user-exists` | WebAuthn 用户存在性 | 无 WebAuthn | 缺口 |
| 182 | 公共/账号 | `GET /v3/public/captcha/email` | 邮箱验证码 | 无 | 缺口 |
| 183 | 公共/账号 | `GET /v3/public/captcha/image` | 图形验证码 | 无验证码服务 | 缺口 |
| 184 | 公共/账号 | `GET /v3/public/captcha/sms` | 短信验证码 | 无 | 缺口 |
| 185 | 公共/账号 | `DELETE /v3/public/trust/person` | 删除账号 | 无 | 缺口 |
| 186 | 公共/账号 | `GET /v3/public/trust/person` | 账号/人员列表 | 身份与账号来自集成（只读） | 部分重合 |
| 187 | 公共/账号 | `POST /v3/public/trust/person` | 新增账号 | 不维护人员主数据 | 缺口 |
| 188 | 公共/账号 | `PUT /v3/public/trust/person` | 修改账号 | 无 | 缺口 |
| 189 | 公共/账号 | `GET /v3/public/trust/person/detail` | 账号详情 | 身份账号视图（只读） | 部分重合 |
| 190 | 公共/账号 | `PUT /v3/public/trust/person/reset-pass` | 重置账号口令 | 无 | 缺口 |
| 191 | 公共/账号 | `PUT /v3/public/trust/person/update-pass` | 修改账号口令 | 无 | 缺口 |
| 192 | 公共/账号 | `GET /v3/public/trust/suggest` | 账号联想 | 无 | 缺口 |
| 193 | 登录与权限 | `POST /v3/user/get-token` | 签发令牌 | 会话 Cookie，无对外令牌签发 | 部分重合 |
| 194 | 登录与权限 | `POST /v3/user/login` | 管理端登录 | /auth/login | 重合 |
| 195 | 登录与权限 | `DELETE /v3/user/logout` | 登出 | /auth/logout | 重合 |
| 196 | 登录与权限 | `GET /v3/user/permission` | 权限点 | RBAC 角色权限（来自角色定义） | 部分重合 |
| 197 | 登录与权限 | `POST /v3/user/reset-password-manager` | 重置自身口令 | 无改密接口 | 缺口 |
| 198 | 系统参数 | `GET /v3/advanced/auth-err-msg` | 认证错误文案 | 认证事件错误码（只读） | 部分重合 |
| 199 | 系统参数 | `GET /v3/advanced/drop-reason` | 下线原因字典 | 无 | 缺口 |
| 200 | 系统参数 | `GET /v3/advanced/init-settings` | 初始化系统参数 | /system/status 等只读状态 | 部分重合 |
| 201 | 系统参数 | `POST /v3/advanced/update-mgr-style` | 管理端样式 | 无 | 缺口 |
| 202 | 系统参数 | `POST /v3/advanced/update-settings` | 更新系统参数 | 配置在部署侧（env/文件） | 部分重合 |
| 203 | 概览 | `GET /v3/dashboard/card` | 概览卡片 | /overview、/violation-dashboard | 重合 |
| 204 | 概览 | `GET /v3/dashboard/chart` | 概览图表 | /activity/overview、趋势接口 | 重合 |

## 结论

剔除 34 条不适用后，真正可比的是 170 条：重合 11、部分重合 55、缺口 104。完全重合只有 11 条，加上部分重合 55 条也不到四成；缺口集中在“登记运营流程”和“管理配置”，不在“识别”本身。

**已经对齐的**：管理端登录/登出、设备台账与详情、登记新增与编辑、操作审计、概览卡片与图表、产品目录只读、在线会话只读。这就是上次“管理员独立登记主流程”迁过来的那几条（`register/single`、`deviceMgr/device`、`register/device-record` ↔ `/endpoints/registrations`）。

**值得补的缺口（按性价比）**：

1. **登记审核流 + 批量登记/批量操作（25 条缺口）**：台账现在只有单条 upsert，没有待审/驳回、模板导入、批量改责任人/状态/删除。不涉及准入下发，风险低，运营价值高。
2. **设备类别字典（6 条，其中 4 条缺口）**：设备类型由识别规则产生，不能人工建类别、排序、删除；扩展字段前端有页面、后端未注册接口（`/v3/setting/extendField`、`/v3/deviceMgr/extendField` 只存在于前端 api 目录），属同类缺口。
3. **组织与位置主数据（12 条，其中 8 条缺口）**：组织来自身份同步（只读），位置只有统计维度，都不能在系统内维护。
4. **管理员与角色管理（13 条，其中 12 条缺口）**：RBAC 依赖 `auth` 文件与固定角色，没有界面化增删改、口令重置和管辖范围。
5. **自助服务（12 条，其中 5 条缺口、5 条只有只读近似）**：语义最贴近“哑终端自助上线”，但工作量最大；204 已选独立登记，可以后置。
6. **设备删除/合并（1 条）**：台账只有 upsert，没有删除；我方有 `merge_status` 字段但没有对应入口。

**不建议接（34 条）**：RADIUS 模板与属性、套餐计费、准入策略下发、访客、在线踢人、超载日志。它们属于 4K/AAA 体系，且本系统观察期明确不发送下线、封禁、解封。

**可以从“部分重合”里低成本捡的**：在线会话只读、认证日志只读视图、采集与 DPI 状态展示、认证错误码映射、SSO（OIDC 已有，CAS/钉钉/金智按客户补）。

**一条边界提醒**：`deviceMgr/online` 与 `online/drop` 这类“踢下线”接口和“只记录、不执行”的产品边界直接冲突，不要为了功能对齐把它们接进来。


