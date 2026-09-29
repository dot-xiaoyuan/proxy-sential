# 旧防代理认证联动接口提取

本轮指定账号：`yuantong`；用户提供认证后 IPv4：`192.168.0.93`。该关联在重新认证后曾经只读确认；最新接口空数组不能证明离线，也不代表永久授权。登录密码不写入代码、配置示例或日志。用户负责门户认证和重新认证。

## 提取依据与能力

| 能力 | 已有接口或代码 | 本轮结论 |
| --- | --- | --- |
| 管理鉴权 | `POST /api/v2/auth/get-access-token`，appId/appSecret | 复用 internal/srunapi 正式应用鉴权；用户登录密码不是管理凭据 |
| 指定账号在线设备 | `/api/v2/base/online-equipment`，user_name；支持 GET，控制器也兼容 POST | 本地认证系统源码 OnlineRadius.onlineList 按账号查询；默认 rad_online_id/user_name/user_ip/add_time/MAC。返回字段由管理端配置控制，默认未包含 session_id/ip6/nas_ip。没有固定快照，不能仅拼接页或根据空页证明全部目标离线 |
| 简略在线清单 | `/api/v2/base/online-data` | searchParams 是返回字段选择，只含 user_name/group_id/ip；不是账号筛选，也没有准确下线必需的原始在线 ID |
| 在线总数 | `/api/v2/base/get-online-total` | 仅健康/连通探针；不能替代会话清单 |
| 管理员下线 | `POST /api/v2/base/online-drop`，user_name/rad_online_id/drop_type | 现有适配已支持。code=0 仅受理，必须独立核验原会话消失；本轮运行配置仅开放 radius，其他类型未验收 |
| 既有在线事件服务 | 8022 TCP、8021/9021 WebSocket；all 全量 + 登录/注销事件 | 协议有 total/pos/count 与结束标记，但本地 buildExportOnlineInfo 默认不导出原始 online ID、会话 ID、登录时间或 IPv6，且内部全量重载周期 30 秒。不能据此声称满足 5 秒权威新鲜度或处置准入 |
| 用户注销 | 未从本轮所核对 SDK/旧防代理找到完整、已验证的管理注销契约 | 未完成；不把管理员下线伪装成用户注销，不映射到账号停用或删除 |

源码位置：

- `dpi-analyze/pkg/component/northbound/setup.go`：旧管理接口 SDK 配置从 Mongo northbound 记录读取；默认 appId/secret 只是缺省初始化值，不是可用生产凭据。
- `dpi-analyze/pkg/users/users.go`：旧账号/IP 关联直接读在线 Redis 字段，不能照搬成新 API 集成。
- `dpi-analyze/pkg/users/hook.go`：旧下线修改在线 Redis 并推送更新/DM 队列；本轮不采用该路径。
- 本机 `srun-api/rest/versions/api/v1/controllers/BaseController.php` 和 `models/OnlineRadius.php`：设备查询、账号过滤、字段配置、原始在线 ID 归属检查。
- 本机 `srun-interface-refactor/srun4kAuthIntf/src/srun_onlineintf/srun_auth_events.go`：既有在线事件字段、分块、结束标记与刷新周期。

这些本地源码不能证明 190 当前部署版本、接口字段配置、白名单和凭据有效；需通过实际接口复核。本轮未 SSH 190、未自动操作门户、未修改认证系统、未发送真实下线请求。

## 已落地的消费适配

`internal/srunapi/inventory_http.go` 增加现有完整在线 API/桥接结果的 HTTPS 读取适配。契约为 online-inventory/v1，显式包含 source instance、观测时间、范围、complete、expected_count 及原始 rows。只接受最多 5 秒的新鲜完整清单；每行要求账号、会话 ID、原始在线 ID、登录代次和有效地址，沿用既有双栈身份与代次转换。部分清单、错误码、重定向、超限、畸形或陈旧数据明确失败，不产生空清单。

私有 native 配置支持 inventory_url/inventory_token，禁止与 redis_url/list/ready 混用，不在 API 失败后回退数据库。加载配置不发起网络请求。旧 Redis 配置仅允许显式 allow_legacy_redis_replay=true 且管理端与 Redis 均为回环地址的隔离回放；非回环地址（包括190）明确拒绝，本轮 190 配置示例改为 API。尚未部署或启用。

该适配只消费既有标准结果，**没有在 190 新建桥接服务**；不能把原生 online-equipment 地址直接填入该配置，它的分页响应不是此完整契约。

## 当前缺失契约与后续验证

4K授权、证书、管理API连通及指定账号只读关联已验证；这些不证明全量权威身份或实际控制通过。管理端五秒同步、共享v3时序切分和持久化复核已实现并部署30，完整清单消费仅在隔离环境验证。

190尚缺现场证明：全接入范围清单的完整性与来源观测时间，准确会话ID/原始在线ID/登录代次，IPv6与接入范围，以及区分查询失败、不完整与目标确实消失的结果契约。最新online-equipment空数组不证明离线；online-data使用GET现场查询成功，返回81条，字段仅group_id/ip/user_name；源码默认分页1000条且逐条读取，无稳定快照契约，不能证明完整权威清单。

人工下线预览/提交与复核、配置、会话指纹的完整绑定尚未完成；真实下线、用户注销与重新认证恢复保持未完成。用户注销仍需独立已部署接口契约。不修改190或用Redis回退补齐这些缺失。
