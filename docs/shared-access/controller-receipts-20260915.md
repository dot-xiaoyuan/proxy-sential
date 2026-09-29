# 控制器完成回执校验（2026-09-15）

## 已确认的问题

Sentinel 执行器和 legacy-northbound 网关原来将任何 HTTP 2xx 视作完成，甚至响应为空、仅包含业务错误码、返回 pending 或登录 HTML 时也可能标记成功并推进策略阶段。

190 原生 online-drop 调用模型的 KernelInterface.userDrop。原生接口的业务返回必须由专用适配器解释并核验实际会话状态；不能把原生 HTTP 200、code=0 或命令受理直接转换为 Sentinel 的最终完成回执。原生支持 radius/proxy/dhcp/portal 下线类型；portal 分支向内核传 user_ip，其他分支使用 online_id。原生账号/会话检查、执行时归属复核和结果对账仍需专门接入，不能退化成无账号校验的共享 IP 封禁。

## 本地修复

新增统一 actionreceipt 校验：

```json
{"action_id":"controller-unique-action-id","status":"completed"}
```

- 远端动作 ID 必须非空，回执最多 1 MiB，必须是唯一 JSON 对象。
- status=completed 表示本次请求操作已完成；succeeded 仅用于执行，revoked 仅用于解除。
- pending、accepted、failed、缺少状态、缺少 ID、未知字段及额外 JSON 均不作为完成回执。
- 执行器保留失败/重试路径及原幂等身份，不置 succeeded/revoked，不推进前置动作成功条件。
- 旧网关仅在收到有效完成回执后写入完成缓存，未确认响应不会缓存为成功。
- 完成缓存增加格式版本。旧无版本缓存及损坏缓存拒绝启动并要求核验，既不自动信任旧结果，也不清空后重发潜在已执行动作。

契约文件：`schemas/action-receipt-v1.schema.json`。这是连接器回执契约收紧，既有适配器仅返回 action_id 的情况需先升级，不能直接沿用。旧缓存需备份并结合原控制器/audit 确认，不能通过删除缓存绕过。

## 测试

- 统一解析器覆盖正常完成、执行/撤销状态不匹配、缺字段、业务错误、pending、冲突字段、额外 JSON 和 HTML。
- 执行器 HTTP 200 负例验证：状态仍待重试、错误保留、没有 succeeded/revoked。
- 网关验证未完成结果不会进入完成缓存，旧/损坏缓存不自动加载。
- 现有签名、幂等、账号动作、撤销沙箱回归适配新的明确完成回执。
- `go test ./...` 与相关 `go test -race` 通过，记录在 `artifacts/shared-access-receipts/`。

## 未完成

本轮尚未实现 190 原生控制器适配器、管理 API 鉴权及会话结果对账，未执行真实控制器处罚。原生异步动作需通过专用适配器查询/回调确认后再返回终态；不能把本轮严格回执校验当作原生动作已接入。

原子幂等、崩溃后不确定动作恢复、限速叠加/新会话继承、人工撤销和控制器实际解除仍按原计划验收。生产未部署，共享自动处罚仍关闭。
